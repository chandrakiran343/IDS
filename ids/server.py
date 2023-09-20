from flask import Flask, request, jsonify
import tensorflow as tf
# import joblib

app = Flask(__name__)

# Load the trained TensorFlow Keras model
# model = joblib.load('random_classifier_model.pkl')
model = tf.keras.models.load_model('./ids.keras')
# print(model)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get data from the request in JSON format
        data = request.get_json()

        # Ensure that the input data matches the model's input shape
        if 'input' not in data:
            return jsonify({'error': 'Missing "input" in request data'}), 400

        # Extract the input data from the JSON request
        input_data = data['input']
        input_data = [input_data]

        # Perform prediction using the loaded model
        predictions = model.predict(input_data)

        # Convert the predictions to a list
        predictions = predictions.tolist()

        print(predictions)

        # Return the predictions as a JSON response
        return jsonify({'predictions': predictions})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
