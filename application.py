import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import joblib
from flask import Flask, request, jsonify, render_template
import os

# Feature extraction function aligned with dataset columns
def extract_features(url):
    try:
        parsed_url = urlparse(url)
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        features = {
            'having_IP_Address': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed_url.netloc) else 0,
            'URL_Length': 1 if len(url) > 54 else -1 if len(url) < 54 else 0,
            'Shortining_Service': 1 if any(s in url.lower() for s in ['bit.ly', 'tinyurl', 'goo.gl']) else -1,
            'having_At_Symbol': 1 if '@' in url else -1,
            'double_slash_redirecting': 1 if '//' in url[7:] else -1,
            'Prefix_Suffix': 1 if '-' in parsed_url.netloc else -1,
            'having_Sub_Domain': 1 if len(parsed_url.netloc.split('.')) > 3 else -1 if len(parsed_url.netloc.split('.')) == 2 else 0,
            'SSLfinal_State': 1 if parsed_url.scheme == 'https' else -1,
            'Domain_registeration_length': 0,  # Requires WHOIS lookup, placeholder
            'Favicon': 1 if soup.find('link', rel='icon') else -1,
            'port': 1 if parsed_url.port else -1,
            'HTTPS_token': 1 if 'https' in url.lower() and parsed_url.scheme != 'https' else -1,
            'Request_URL': 1 if any('http' in tag.get('src', '') for tag in soup.find_all(['img', 'script'])) else -1,
            'URL_of_Anchor': 1 if any(tag.get('href', '').startswith('#') for tag in soup.find_all('a')) else -1,
            'Links_in_tags': 1 if any(tag.get('href', '').startswith('http') for tag in soup.find_all(['link', 'script'])) else -1,
            'SFH': 1 if any(form.get('action', '').startswith('http') for form in soup.find_all('form')) else -1,
            'Submitting_to_email': 1 if any('mailto:' in form.get('action', '') for form in soup.find_all('form')) else -1,
            'Abnormal_URL': 1 if parsed_url.netloc.lower() not in url.lower() else -1,
            'Redirect': 1 if len(response.history) > 0 else 0,
            'on_mouseover': 1 if 'onmouseover' in response.text.lower() else -1,
            'RightClick': 1 if 'oncontextmenu' in response.text.lower() else -1,
            'popUpWidnow': 1 if 'window.open' in response.text.lower() else -1,
            'Iframe': 1 if soup.find('iframe') else -1,
            'age_of_domain': 0,  # Requires WHOIS lookup, placeholder
            'DNSRecord': 0,  # Requires DNS lookup, placeholder
            'web_traffic': 0,  # Requires external API, placeholder
            'Page_Rank': 0,  # Requires external API, placeholder
            'Google_Index': 1,  # Assume indexed, placeholder
            'Links_pointing_to_page': 0,  # Requires external API, placeholder
            'Statistical_report': 0  # Requires external data, placeholder
        }
        return features
    except Exception as e:
        print(f"Error extracting features from {url}: {e}")
        # Return default values if URL is inaccessible
        return {
            'having_IP_Address': -1,
            'URL_Length': -1,
            'Shortining_Service': -1,
            'having_At_Symbol': -1,
            'double_slash_redirecting': -1,
            'Prefix_Suffix': -1,
            'having_Sub_Domain': -1,
            'SSLfinal_State': -1,
            'Domain_registeration_length': 0,
            'Favicon': -1,
            'port': -1,
            'HTTPS_token': -1,
            'Request_URL': -1,
            'URL_of_Anchor': -1,
            'Links_in_tags': -1,
            'SFH': -1,
            'Submitting_to_email': -1,
            'Abnormal_URL': -1,
            'Redirect': 0,
            'on_mouseover': -1,
            'RightClick': -1,
            'popUpWidnow': -1,
            'Iframe': -1,
            'age_of_domain': 0,
            'DNSRecord': 0,
            'web_traffic': 0,
            'Page_Rank': 0,
            'Google_Index': 1,
            'Links_pointing_to_page': 0,
            'Statistical_report': 0
        }

# Training function
def train_model(dataset_path):
    try:
        # Verify dataset exists
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset not found at {dataset_path}")
        
        # Load dataset
        df = pd.read_csv(dataset_path)
        
        # Verify expected columns
        expected_columns = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
            'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
            'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
            'Statistical_report', 'Result'
        ]
        if not all(col in df.columns for col in expected_columns):
            missing_cols = [col for col in expected_columns if col not in df.columns]
            raise ValueError(f"Missing columns in dataset: {missing_cols}")
        
        # Split features and target
        X = df.drop('Result', axis=1)
        y = df['Result']
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train Random Forest
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Save model
        joblib.dump(model, 'phishing_model.pkl')
        
        # Print accuracy
        y_pred = model.predict(X_test)
        print(f"Model Accuracy: {accuracy_score(y_test, y_pred):.2f}")
        
        return model
    except Exception as e:
        print(f"Error training model: {e}")
        return None

# Flask API
app = Flask(__name__)
model = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    global model
    try:
        if model is None:
            if not os.path.exists('phishing_model.pkl'):
                raise FileNotFoundError("Model file 'phishing_model.pkl' not found")
            model = joblib.load('phishing_model.pkl')
        
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required in JSON payload'}), 400
        
        url = data['url']
        features = extract_features(url)
        feature_array = np.array([list(features.values())])
        
        prediction = model.predict(feature_array)[0]
        probability = model.predict_proba(feature_array)[0][1]
        
        return jsonify({
            'url': url,
            'is_phishing': bool(prediction == 1),
            'probability': float(probability)
        })
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

if __name__ == '__main__':
    # Train model with your dataset
    dataset_path = 'C:/Users/Che Blaise/Desktop/final/Phishing_Websites_Data.csv'  # Absolute path
    model = train_model(dataset_path)
    if model is None:
        print("Failed to start server due to training error")
    else:
        # Run Flask app
        app.run(debug=True, host='0.0.0.0', port=5000)