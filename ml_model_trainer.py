import pandas as pd
import numpy as np
import pickle
import os
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.utils import to_categorical

# --- Configuration ---
DATA_FILE = "syscall_dataset.csv"
MODEL_DIR = "models"
SEQUENCE_LENGTH = 5  # Number of past calls to look at to predict the next one

# Ensure model directory exists
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

def load_and_preprocess():
    print("[*] Loading data...")
    if not os.path.exists(DATA_FILE):
        raise FileNotFoundError(f"{DATA_FILE} not found! Did you run Phase 1?")
    
    df = pd.read_csv(DATA_FILE)
    
    # 1. Encode Syscall Names (read -> 1, write -> 2)
    le = LabelEncoder()
    df['syscall_encoded'] = le.fit_transform(df['syscall'])
    
    # 2. Normalize Latency (0.0001 -> 0.05)
    scaler = MinMaxScaler()
    df['latency_norm'] = scaler.fit_transform(df[['latency']])
    
    # Save the encoder and scaler for Phase 3
    with open(f"{MODEL_DIR}/label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)
    with open(f"{MODEL_DIR}/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
        
    print(f"[+] Data loaded: {len(df)} rows. Unique syscalls: {len(le.classes_)}")
    return df, le, scaler

def train_anomaly_detector(df):
    print("\n[*] Training Isolation Forest for Anomaly Detection...")
    
    # We use 'syscall_encoded' and 'latency_norm' as features
    X = df[['syscall_encoded', 'latency_norm']].values
    
    # Contamination is the expected % of outliers in the training set (usually low)
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso_forest.fit(X)
    
    # Save the model
    with open(f"{MODEL_DIR}/isolation_forest.pkl", "wb") as f:
        pickle.dump(iso_forest, f)
        
    print("[+] Isolation Forest trained and saved.")

def create_sequences(data, seq_length):
    X, y = [], []
    for i in range(len(data) - seq_length):
        X.append(data[i:i+seq_length])
        y.append(data[i+seq_length])
    return np.array(X), np.array(y)

def train_sequence_predictor(df, num_classes):
    print("\n[*] Training LSTM for Sequence Prediction...")
    
    data = df['syscall_encoded'].values
    X, y = create_sequences(data, SEQUENCE_LENGTH)
    
    # One-hot encode the target (y)
    y = to_categorical(y, num_classes=num_classes)
    
    # Reshape X for LSTM [samples, time steps, features]
    # We add a dimension because we only have 1 feature (syscall type)
    X = X.reshape((X.shape[0], X.shape[1], 1))
    
    # Build LSTM Model
    model = Sequential([
        LSTM(64, input_shape=(SEQUENCE_LENGTH, 1), return_sequences=False),
        Dropout(0.2),
        Dense(32, activation='relu'),
        Dense(num_classes, activation='softmax')
    ])
    
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    
    # Train
    history = model.fit(X, y, epochs=10, batch_size=32, validation_split=0.2, verbose=1)
    
    # Save Model
    model.save(f"{MODEL_DIR}/lstm_model.keras") # .keras is the modern format
    print("[+] LSTM Model trained and saved.")
    
    return history

def plot_results(history):
    print("\n[*] Plotting training results...")
    plt.figure(figsize=(10, 5))
    plt.plot(history.history['accuracy'], label='Accuracy')
    plt.plot(history.history['val_accuracy'], label='Val Accuracy')
    plt.title('LSTM Model Training Accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend()
    plt.savefig(f"{MODEL_DIR}/training_plot.png")
    print(f"[+] Plot saved to {MODEL_DIR}/training_plot.png")

def main():
    try:
        df, le, scaler = load_and_preprocess()
        
        # Train Model 1: Anomaly Detector (Unsupervised)
        train_anomaly_detector(df)
        
        # Train Model 2: Sequence Predictor (Supervised)
        num_classes = len(le.classes_)
        history = train_sequence_predictor(df, num_classes)
        
        plot_results(history)
        
        print("\n--- Phase 2 Complete ---")
        print(f"Models saved in '{MODEL_DIR}/' directory.")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()