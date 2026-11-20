
import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# Find the main project directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_PATH = os.path.join(BASE_DIR, "dataset", "messages.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "scam_message_model.pkl")


# Create models folder if it doesn't exist
os.makedirs(MODEL_DIR, exist_ok=True)


# Load dataset
data = pd.read_csv(DATASET_PATH)

# Check dataset columns
required_columns = {"message", "label"}

if not required_columns.issubset(data.columns):
    raise ValueError("Dataset must contain message and label columns.")

data = data.dropna(subset=["message", "label"])
data["message"] = data["message"].astype(str)
data["label"] = data["label"].astype(str).str.lower().str.strip()

# Validate labels
if set(data["label"].unique()) != {"safe", "scam"}:
    raise ValueError("Labels must contain both 'safe' and 'scam'.")

if data["label"].value_counts().min() < 2:
    raise ValueError("At least two examples per class are required.")


# Separate input and output
X = data["message"]
y = data["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# Create machine learning pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        max_features=5000
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        random_state=42
    ))
])


# Train model
print("Training scam detection model...")

model.fit(X_train, y_train)


# Evaluate model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel Evaluation")
print("----------------")
print(f"Test accuracy: {accuracy:.2%}")
print("\nClassification Report:")
print(classification_report(y_test, predictions, zero_division=0))


# Save trained model
joblib.dump(model, MODEL_PATH)

print("\nModel training completed!")
print("Model saved at:", MODEL_PATH)
