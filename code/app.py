import streamlit as st
import pandas as pd
import json
import joblib
from datetime import datetime
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt
import seaborn as sns
import os
import chromadb
from sentence_transformers import SentenceTransformer
from vertexai.preview.generative_models import GenerativeModel
from google.cloud import aiplatform


st.set_page_config(page_title="CloudTrail Security Analyzer", layout="wide")
MODEL_PATH = "models/isolation_forest.pkl"
CHROMA_PATH = "./chroma_store"
COLLECTION_NAME = "cloudtrail_logs"

st.markdown("""
    <style>
    html, body, [class*="css"]  {
        font-family: 'Segoe UI', sans-serif;
        background-color: #f5f5f5;
    }
    .block-container { padding: 2rem; }
    </style>
""", unsafe_allow_html=True)


model: Pipeline = joblib.load(MODEL_PATH)
aiplatform.init(project="vent-457117", location="us-central1")
llm = GenerativeModel("gemini-1.5-pro")
embedder = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_collection(COLLECTION_NAME)

uploaded_file = st.sidebar.file_uploader("Upload CloudTrail JSON", type="json")

@st.cache_data
def parse_uploaded(file):
    data = json.load(file)
    records = data.get("Records", [])
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
    return df

def score(df):
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
    df["hour"] = df["eventTime"].dt.hour.fillna(-1)
    df["dayofweek"] = df["eventTime"].dt.dayofweek.fillna(-1)
    df = df.drop(columns=["eventTime"])
    df["score"] = model["model"].decision_function(model["preprocessor"].transform(df))
    df["is_anomaly"] = model["model"].predict(model["preprocessor"].transform(df))
    return df[df["is_anomaly"] == -1]

def anomaly_charts(anomalies):
    st.subheader("Anomaly Breakdown")
    col1, col2 = st.columns(2)

    with col1:
        fig, ax = plt.subplots()
        sns.countplot(data=anomalies, y="eventName", order=anomalies["eventName"].value_counts().index[:10], ax=ax)
        ax.set_title("Top Anomalous Event Names")
        st.pyplot(fig)

    with col2:
        fig, ax = plt.subplots()
        sns.countplot(data=anomalies, y="sourceIPAddress", order=anomalies["sourceIPAddress"].value_counts().index[:10], ax=ax)
        ax.set_title("Suspicious Source IPs")
        st.pyplot(fig)

def query_logs_with_gemini(question, top_k=5):
    q_embedding = embedder.encode([question])[0].tolist()
    results = collection.query(query_embeddings=[q_embedding], n_results=top_k)
    logs = results["documents"][0]
    context = "\n\n".join(logs)

    prompt = f"""You are a cybersecurity assistant. Based on these logs, answer:

{context}

Q: {question}
A:"""

    response = llm.generate_content(prompt)
    return response.text

def generate_report(anomalies):
    time_str = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename = f"report_{time_str}.txt"
    summary = anomalies.groupby("eventName").size().sort_values(ascending=False).head(5)
    with open(filename, "w") as f:
        f.write("CloudTrail Anomaly Report\n")
        f.write("="*40 + "\n")
        f.write(f"Anomalies: {len(anomalies)}\n\n")
        f.write("Top Event Types:\n")
        f.write(summary.to_string())
    return filename

# --- App Layout ---
tabs = st.tabs(["Dashboard", "Ask AI"])

if uploaded_file:
    df_logs = parse_uploaded(uploaded_file)
    anomalies = score(df_logs.copy())

    with tabs[0]:
        st.header(" Anomaly Detection Dashboard")
        st.dataframe(anomalies, use_container_width=True)
        anomaly_charts(anomalies)

        csv = anomalies.to_csv(index=False).encode("utf-8")
        st.download_button("Download Anomalies CSV", csv, "anomalies.csv")

        if st.button("Generate Report"):
            path = generate_report(anomalies)
            with open(path) as f:
                st.download_button("Download Report", f.read(), file_name=path)

    with tabs[1]:
        st.header("Ask a Security Question")
        user_q = st.text_input("Ask something about log behavior")
        if st.button("Ask AI"):
            st.write(query_logs_with_gemini(user_q))
else:
    st.info("Upload a CloudTrail JSON file to get started.")
