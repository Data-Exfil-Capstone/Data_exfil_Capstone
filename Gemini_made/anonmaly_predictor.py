# 1. Import Necessary Libraries
import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration ---
DATA_TO_TEST_PATH = '..\malware-detection-with-deep-learning-autoencoder\SAMPLES\\benign_binary.csv' # The new data you want to classify
MODEL_PATH = 'autoencoder_model.h5'
SCALER_PATH = 'scaler.pkl'
THRESHOLD_PATH = 'threshold.txt'
OUTPUT_PREDICTIONS_PATH = 'predictions.csv'

# 2. Load Saved Artifacts
print("--- Loading saved model, scaler, and threshold ---")
try:
    model = tf.keras.models.load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(THRESHOLD_PATH, 'r') as f:
        threshold = float(f.read())
except (IOError, FileNotFoundError) as e:
    print(f"Error loading artifacts: {e}")
    print("Please run 'train_autoencoder.py' first to generate the necessary files.")
    exit()

print(f"Model, scaler, and threshold (={threshold:.5f}) loaded successfully.")

# 3. Load and Preprocess New Data
print(f"\n--- Loading new data from {DATA_TO_TEST_PATH} ---")
try:
    df_test = pd.read_csv(DATA_TO_TEST_PATH)
except FileNotFoundError:
    print(f"Error: The file '{DATA_TO_TEST_PATH}' was not found.")
    print("Please create this file with data you want to test.")
    exit()

# Ensure the columns match the training data
# (A more robust solution would save and check column order)
X_test = df_test.values

# IMPORTANT: Use the *same* scaler that was fitted on the training data
X_test_scaled = scaler.transform(X_test)

# 4. Make Predictions
print("\n--- Classifying new data ---")
predictions = model.predict(X_test_scaled)
mae = np.mean(np.abs(X_test_scaled - predictions), axis=1)

# 5. Classify as Benign or Anomaly
df_test['reconstruction_error'] = mae
df_test['prediction'] = np.where(df_test['reconstruction_error'] > threshold, 'Anomalous', 'Benign')

print("Classification complete. Results:")
print(df_test[['reconstruction_error', 'prediction']].head())
print("\nDistribution of predictions:")
print(df_test['prediction'].value_counts())

# 6. Save Results
df_test.to_csv(OUTPUT_PREDICTIONS_PATH, index=False)
print(f"\nResults with predictions saved to '{OUTPUT_PREDICTIONS_PATH}'")

# 7. Visualization of Reconstruction Errors
plt.figure(figsize=(12, 6))
sns.histplot(df_test['reconstruction_error'], bins=50, kde=True, color='purple')
plt.axvline(threshold, color='red', linestyle='--', linewidth=2, 
            label=f'Threshold = {threshold:.5f}')
plt.title('Distribution of Reconstruction Errors on Test Data')
plt.xlabel('Mean Absolute Error (MAE)')
plt.ylabel('Frequency')
plt.legend()
plt.grid(True)
plt.show()

# Optional: Show proportion of anomalies vs benign
plt.figure(figsize=(6, 6))
df_test['prediction'].value_counts().plot(kind='pie', autopct='%1.1f%%', 
                                          colors=['green', 'orange'], 
                                          labels=['Benign', 'Anomalous'])
plt.title('Prediction Distribution')
plt.ylabel('')
plt.show()