# models/trainer.py

import pandas as pd
import pymysql
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def train_model():
    try:
        # ✅ Connect to MySQL and read data
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='',
            database='phishing_db'
        )
        df = pd.read_sql("SELECT * FROM phishing_data", conn)
        conn.close()

        # ✅ Split features and target
        X = df.drop('Result', axis=1)
        y = df['Result']

        # ✅ Stratified train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # ✅ Train model with class balancing
        model = RandomForestClassifier(
            n_estimators=100,
            class_weight='balanced',
            random_state=42
        )
        model.fit(X_train, y_train)

        # ✅ Evaluate model
        y_pred = model.predict(X_test)
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred))

        # ✅ Save trained model
        joblib.dump(model, 'phishing_model.pkl')
        print("✅ Model trained and saved as phishing_model.pkl")

        return model

    except Exception as e:
        print(f"❌ Training failed: {e}")
        return None
