const tf = require('@tensorflow/tfjs-node');


const run = async () => {

    // const file = 

    const model = await tf.loadLayersModel('file://./ids_model/model.json')

    console.log(model)

}

run()