from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import os
from urllib.parse import urlparse
import pymysql

from features.extractor import extract_features
from models.trainer import train_model  # This now loads data from MySQL internally

app = Flask(__name__)
model = None

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ('http', 'https'), parsed.netloc])
    except:
        return False

# ✅ Save prediction result to appropriate database table
def log_to_database(url, probability, is_phishing):
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='',
            database='phishing_db'
        )
        cursor = conn.cursor()

        table = 'phishing_sites' if is_phishing else 'safe_sites'
        sql = f"INSERT INTO {table} (url, probability) VALUES (%s, %s)"
        cursor.execute(sql, (url, probability))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"❌ Failed to log to database: {e}")

@app.route('/')
def home():
    return render_template('index.html')  # Make sure templates/index.html exists

@app.route('/predict', methods=['POST'])
def predict():
    global model
    try:
        if model is None:
            if not os.path.exists('phishing_model.pkl'):
                return jsonify({'error': 'Model not found. Train it first.'}), 500
            model = joblib.load('phishing_model.pkl')

        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url']

        if not is_valid_url(url):
            return jsonify({'error': 'This is not a valid website URL'}), 400

        # Extract features
        features = extract_features(url)
        input_df = pd.DataFrame([features])

        # Match feature order with model
        model_features = model.feature_names_in_ if hasattr(model, 'feature_names_in_') else input_df.columns
        input_df = input_df[model_features]

        # Prediction
        prediction = model.predict(input_df)[0]
        probability = model.predict_proba(input_df)[0][1]
        is_phishing = bool(prediction == 1)

        # ✅ Log to database
        log_to_database(url, probability, is_phishing)

        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'probability': float(round(probability, 3)),
            'features': features  # ✅ Send feature breakdown to frontend
        })

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

if __name__ == '__main__':
    print("Training model from MySQL...")
    model = train_model()
    if model:
        print("Model ready. Starting Flask app...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to train model.")
