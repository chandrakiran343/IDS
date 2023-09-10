const pcap = require('pcap');
const fs = require('fs');
const axios = require('axios');
const tf = require('@tensorflow/tfjs-node');

// Create a session for capturing packets on a network interface (e.g., 'eth0' or 'wlan0')
const pcapSession = pcap.createSession('wlp0s20f3', 'tcp or udp');

const listenPort = 3000;
let packetCount = 0
let totalBytes = 0;
let startTime = Date.now();

let model
const record = {

}

const protocolMappings =
    { 'udp': 117, 'arp': 6, 'tcp': 111, 'igmp': 41, 'ospf': 77, 'sctp': 95, 'gre': 32, 'ggp': 30, 'ip': 44, 'ipnip': 49, 'st2': 106, 'argus': 4, 'chaos': 13, 'egp': 23, 'emcon': 25, 'nvp': 76, 'pup': 85, 'xnet': 127, 'mux': 72, 'dcn': 19, 'hmp': 33, 'prm': 83, 'trunk-1': 114, 'trunk-2': 115, 'xns-idp': 128, 'leaf-1': 64, 'leaf-2': 65, 'irtp': 57, 'rdp': 88, 'netblt': 74, 'mfe-nsp': 67, 'merit-inp': 66, '3pc': 0, 'idpr': 37, 'ddp': 20, 'idpr-cmtp': 38, 'tp++': 113, 'ipv6': 51, 'sdrp': 96, 'ipv6-frag': 52, 'ipv6-route': 55, 'idrp': 39, 'mhrp': 68, 'i-nlsp': 34, 'rvd': 90, 'mobile': 70, 'narp': 73, 'skip': 99, 'tlsp': 112, 'ipv6-no': 53, 'any': 3, 'ipv6-opts': 54, 'cftp': 12, 'sat-expak': 91, 'ippc': 50, 'kryptolan': 61, 'sat-mon': 92, 'cpnx': 16, 'wsn': 126, 'pvp': 86, 'br-sat-mon': 10, 'sun-nd': 108, 'wb-mon': 125, 'vmtp': 122, 'ttp': 116, 'vines': 120, 'nsfnet-igp': 75, 'dgp': 22, 'eigrp': 24, 'tcf': 110, 'sprite-rpc': 103, 'larp': 63, 'mtp': 71, 'ax.25': 7, 'ipip': 47, 'aes-sp3-d': 2, 'micp': 69, 'encap': 26, 'pri-enc': 82, 'gmtp': 31, 'ifmp': 40, 'pnni': 81, 'qnx': 87, 'scps': 94, 'cbt': 11, 'bbn-rcc': 8, 'igp': 42, 'bna': 9, 'swipe': 109, 'visa': 121, 'ipcv': 46, 'cphb': 15, 'iso-tp4': 60, 'wb-expak': 124, 'sep': 98, 'secure-vmtp': 97, 'xtp': 129, 'il': 43, 'rsvp': 89, 'unas': 118, 'fc': 28, 'iso-ip': 59, 'etherip': 27, 'pim': 79, 'aris': 5, 'a/n': 1, 'ipcomp': 45, 'snp': 102, 'compaq-peer': 14, 'ipx-n-ip': 56, 'pgm': 78, 'vrrp': 123, 'l2tp': 62, 'zero': 130, 'ddx': 21, 'iatp': 35, 'stp': 107, 'srp': 105, 'uti': 119, 'sm': 100, 'smp': 101, 'isis': 58, 'ptp': 84, 'fire': 29, 'crtp': 17, 'crudp': 18, 'sccopmce': 93, 'iplt': 48, 'pipe': 80, 'sps': 104, 'ib': 36 }

const stateMappings = {
    'INT': 4, 'FIN': 3, 'REQ': 5, 'ACC': 0, 'CON': 2, 'RST': 6, 'CLO': 1
}

const serviceMappings = {
    '-': 0, 'http': 5, 'ftp': 3, 'ftp-data': 4, 'smtp': 9, 'pop3': 7, 'dns': 2, 'snmp': 10,
    'ssl': 12, 'dhcp': 1, 'irc': 6, 'radius': 8, 'ssh': 11
}

const modelInput = {
    "protocol": 0,
    "service": 0,
    "state": 0,
    "rate": 0,
    "sttl": 0,
    "dload": 0,
    "swin": 0,
    "stcpb": 0,
    "dtcpb": 0,
    "dwin": 0,
    "ct_state_ttl": 0,
}


// Handle incoming packets
pcapSession.on('packet', (rawPacket) => {
    try {
        const packet = pcap.decode.packet(rawPacket);
        if (
            packet.payload.payload 
            && // Check for a valid TCP packet
            (packet.payload.payload.payload?.dport === listenPort || packet.payload.payload.payload?.sport === listenPort)
        ) {

            packetCount++;

            // Calculate the elapsed time since the program started
            const currentTime = Date.now();
            const elapsedTime = (currentTime - startTime) / 1000; // Convert to seconds

            // Calculate the packet rate (packets per second)
            const packetRate = packetCount / elapsedTime;
            const ipHeader = packet.payload.payload;


            const dataSize = ipHeader.length - ipHeader.headerLength;
            totalBytes += dataSize;



            // calculate source time to live
            const ttl = ipHeader.ttl;
            const ct_state_ttl = 255 - ttl;

            const bps = (totalBytes * 8) / elapsedTime;

            modelInput.dload = bps;

            // Increment the totalBytes with the payload size

            modelInput.rate = packetRate;

            modelInput.swin = ipHeader.payload.windowSize;
            modelInput.dwin = ipHeader.payload.windowSize;
            modelInput.stcpb = ipHeader.payload.seqno;
            modelInput.dtcpb = ipHeader.payload.ackno;
            if (ipHeader.protocol === 6) {
                const tcpHeader = ipHeader.payload;
                modelInput.protocol = protocolMappings["tcp"];
            }
            if (ipHeader.protocol === 17) {
                const udpHeader = ipHeader.payload;
                modelInput.protocol = protocolMappings["udp"];
            }

            modelInput.sttl = ipHeader.ttl;

            switch (ipHeader.payload.dport) {
                case 21:
                    modelInput.service = serviceMappings["ftp"];
                    break;
                case 22:
                    modelInput.service = serviceMappings["ssh"];
                    break;
                case 25:
                    modelInput.service = serviceMappings["smtp"];
                    break;
                case 53:
                    modelInput.service = serviceMappings["dns"];
                    break;
                case 80:
                    modelInput.service = serviceMappings["http"];
                    break;
                default:
                    modelInput.service = serviceMappings["-"];
                    break;
            }

            const flags = ipHeader.payload.flags

            if (flags?.syn && !flags?.ack) {
                modelInput.state = stateMappings["INT"]
            } else if (flags?.fin) {
                modelInput.state = stateMappings["FIN"]
            }
            else if (flags?.rst) {
                modelInput.state = stateMappings["RST"]
            }

            else if (flags?.syn && flags?.ack) {
                modelInput.state = stateMappings["ACC"]
            } else if (flags?.fin && flags?.ack) {
                modelInput.state = stateMappings["CLO"]
            } else if (flags?.ack) {
                modelInput.state = stateMappings["CON"]
            }

            const payload = packet.payload.payload.payload

            console.log(modelInput);

            // runModel(modelInput);
            // append the packet to a file
            fs.appendFile('packets.json', JSON.stringify(packet) + '\n', (err) => {
                if (err) throw err;
            });

            // send a POST request to the server with modelInput as json

            // if(modelInput.dload >= 100000)
            axios.post('http://127.0.0.1:5000/predict', {input: Object.values(modelInput)}).then((res)=>{
                console.log(res.data)
            })


        }

    } catch (error) {
        console.error('Error decoding packet:', error);
    }
});

// const testInput = {
//     "protocol": 111,
//     "service": 9,
//     "state": 3,
//     "rate": 1576.248848,
//     "sttl": 31,
//     "dload": 4.427354e+05,
//     "swin": 255,
//     "stcpb": 4074271478,
//     "dtcpb": 4079596931,
//     "dwin": 255,
//     "ct_state_ttl": 0,
// }


// const runModel = async (testInput) => {

//     // const input = tf.tensor([Object.values(testInput)]);

//     // reshape input to [1,11]

//     const input = tf.tensor([Object.values(testInput)]).reshape([1, 11]);
//     const result =  model.predict(input);

//     // console.log(result);
//     // result.print()

//     console.log(await result.data())
// }

// const init = async () => {
//     model = await tf.loadLayersModel('file://./ids_model/model.json')

    
// }

// init();