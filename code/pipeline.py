import os
import json
import pandas as pd
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from joblib import dump


DATA_DIR = "./training_data"
CHROMA_PATH = "./chroma_store"
MODEL_OUT = "models/isolation_forest.pkl"
COLLECTION_NAME = "cloudtrail_logs"


os.makedirs(CHROMA_PATH, exist_ok=True)
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
embedder = SentenceTransformer("all-MiniLM-L6-v2")
embedding_func = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

def build_vector_store():
    try:
        chroma_client.get_collection(COLLECTION_NAME)
        print("✅ ChromaDB collection already exists. Skipping embedding.")
        return
    except:
        pass

    collection = chroma_client.create_collection(name=COLLECTION_NAME, embedding_function=embedding_func)

    all_text = []
    ids = []
    i = 0
    for file in os.listdir(DATA_DIR):
        if file.endswith(".json"):
            with open(os.path.join(DATA_DIR, file)) as f:
                records = json.load(f).get("Records", [])
                for r in records:
                    doc = json.dumps(r)
                    all_text.append(doc)
                    ids.append(f"rec-{i}")
                    i += 1

    print("Generating embeddings and storing in ChromaDB...")
    for batch in range(0, len(all_text), 1000):
        collection.add(documents=all_text[batch:batch+1000], ids=ids[batch:batch+1000])
    print("✅ Embeddings stored.")


def load_feature_df():
    frames = []
    for file in os.listdir(DATA_DIR):
        if file.endswith(".json"):
            with open(os.path.join(DATA_DIR, file)) as f:
                records = json.load(f).get("Records", [])
                df = pd.DataFrame([{
                    "eventTime": r.get("eventTime"),
                    "eventName": r.get("eventName"),
                    "eventSource": r.get("eventSource"),
                    "sourceIPAddress": r.get("sourceIPAddress"),
                    "awsRegion": r.get("awsRegion"),
                    "errorCode": r.get("errorCode", "None"),
                    "userType": r.get("userIdentity", {}).get("type", "Unknown"),
                    "accessKeyId": r.get("userIdentity", {}).get("accessKeyId", "NA"),
                    "userAgent": r.get("userAgent", "NA")
                } for r in records])
                frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
    df["hour"] = df["eventTime"].dt.hour.fillna(-1)
    df["dayofweek"] = df["eventTime"].dt.dayofweek.fillna(-1)
    df = df.drop(columns=["eventTime"])
    return df

def train_model():
    df = load_feature_df()
    categorical = ["eventName", "eventSource", "sourceIPAddress", "awsRegion",
                   "errorCode", "userType", "accessKeyId", "userAgent"]
    numeric = ["hour", "dayofweek"]

    preprocessor = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
        ("num", SimpleImputer(strategy="mean"), numeric)
    ])

    complex_model = IsolationForest(
        n_estimators=500,
        max_samples='auto',
        max_features=1.0,
        contamination=0.01,
        bootstrap=True,
        n_jobs=-1,
        random_state=42,
        verbose=1
    )

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("model", complex_model)
    ])

    print("Training complex Isolation Forest model... (this may take time)")
    pipeline.fit(df)
    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    dump(pipeline, MODEL_OUT)
    print(f"✅ Model trained and saved to {MODEL_OUT}")

if __name__ == "__main__":
    build_vector_store()
    train_model()
