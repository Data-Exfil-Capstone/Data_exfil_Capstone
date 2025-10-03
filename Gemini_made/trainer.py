# 1. Import Necessary Libraries
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.losses import MeanAbsoluteError
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

# --- Configuration ---
BENIGN_DATA_PATH = './benign_data.csv'
MODEL_SAVE_PATH = 'autoencoder_model.h5'
SCALER_SAVE_PATH = 'scaler.pkl'
THRESHOLD_SAVE_PATH = 'threshold.txt'

# 2. Load and Preprocess Custom Data
print(f"--- Loading benign data from {BENIGN_DATA_PATH} ---")
try:
    df_benign = pd.read_csv(BENIGN_DATA_PATH)
except FileNotFoundError:
    print(f"Error: The file '{BENIGN_DATA_PATH}' was not found.")
    print("Please make sure your benign data CSV is in the same directory and named correctly.")
    exit()

print("Benign Data Head:")
print(df_benign.head())

# All columns are assumed to be numerical features
features = df_benign.columns
X = df_benign[features].values

# Scale the data to a  range
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

INPUT_DIM = X_scaled.shape[1]
print(f"\nData successfully loaded and scaled. Number of features: {INPUT_DIM}")

# 3. Splitting the Data
# Split the benign data into a training set and a validation set
X_train, X_val = train_test_split(X_scaled, test_size=0.2, random_state=42)

print(f"Shape of training data: {X_train.shape}")
print(f"Shape of validation data: {X_val.shape}")

# 4. Model Definition (CORRECTED SECTION)
# Define the autoencoder architecture: Input -> Encoder(6) -> Bottleneck(2) -> Decoder(6) -> Output
autoencoder = Sequential([
    Dense(6, activation='relu', input_shape=(INPUT_DIM,)),  # Encoder
    Dense(2, activation='relu'),                            # Bottleneck
    Dense(6, activation='relu'),                            # Decoder
    Dense(INPUT_DIM, activation='sigmoid')                  # Output (same size as input)
])

# 5. Model Compilation
autoencoder.compile(optimizer='adam', loss=MeanAbsoluteError())

print("\n--- Model Architecture ---")
autoencoder.summary()

# 6. Training the Model
print("\n--- Training Model on Benign Data ---")
history = autoencoder.fit(
    X_train,
    X_train,
    epochs=50,
    batch_size=32,
    shuffle=True,
    validation_data=(X_val, X_val),
    verbose=1
)

# 7. Determine Anomaly Threshold
print("\n--- Determining Anomaly Threshold ---")
# Get reconstruction errors on the validation set (unseen benign data)
X_val_predictions = autoencoder.predict(X_val)
mae_val = np.mean(np.abs(X_val - X_val_predictions), axis=1)

# Set the threshold at the 99th percentile of validation errors
threshold = np.quantile(mae_val, 0.99)
print(f"Anomaly Detection Threshold (99th percentile of validation errors): {threshold:.5f}")
print("Any new data with a reconstruction error above this value will be flagged as an anomaly.")

# Visualize the distribution of reconstruction errors on validation data
plt.figure(figsize=(12, 6))
sns.histplot(mae_val, bins=50, kde=True, color='blue')
plt.axvline(threshold, color='red', linestyle='--', linewidth=2, label=f'Threshold = {threshold:.5f}')
plt.title('Distribution of Reconstruction Errors on Benign Validation Data')
plt.xlabel('Mean Absolute Error (MAE)')
plt.ylabel('Frequency')
plt.legend()
plt.grid(True)
plt.show()

# 8. Save Model, Scaler, and Threshold
print("\n--- Saving artifacts for prediction ---")
autoencoder.save(MODEL_SAVE_PATH)
joblib.dump(scaler, SCALER_SAVE_PATH)
with open(THRESHOLD_SAVE_PATH, 'w') as f:
    f.write(str(threshold))

print(f"Model saved to: {MODEL_SAVE_PATH}")
print(f"Scaler saved to: {SCALER_SAVE_PATH}")
print(f"Threshold saved to: {THRESHOLD_SAVE_PATH}")
print("\nTraining complete. You can now use 'predict_anomalies.py' to test new data.")