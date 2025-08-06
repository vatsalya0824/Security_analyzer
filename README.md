
# CloudTrail Security Analyzer

A scalable, AI-powered system that analyzes AWS CloudTrail logs using unsupervised anomaly detection and natural language queries to uncover suspicious activities.

![Image](https://github.com/user-attachments/assets/9ae87a76-45f5-486e-b04f-2fdf7608def0)

---

## Overview

Modern cloud environments generate vast volumes of log data. Traditional log analysis tools struggle to handle novel attack patterns and zero-day exploits. **CloudTrail Security Analyzer** bridges that gap using:

-  **Unsupervised anomaly detection** via Isolation Forest  
-  **Natural language querying** via Retrieval-Augmented Generation (RAG)  
-  **Interactive dashboards** via Streamlit  
-  **AI-assisted summarization** using Gemini 1.5 Pro

---

##  Objectives

1. Detect anomalies in CloudTrail logs indicating potential threats  
2. Allow human-friendly log querying using natural language  
3. Visualize trends and flagged anomalies with interactive dashboards  

---

##  Architecture

The system is built on a modular stack consisting of:

###  Data Ingestion & Parsing

- Parses deeply nested AWS CloudTrail JSON logs (up to 4 levels)
- Extracts features like IP entropy, geolocation variance, and API usage frequency

###  Anomaly Detection

- Uses **Isolation Forest** (Scikit-learn) for unsupervised detection  
- Prioritizes incidents involving high-risk API calls or rare IP sources  

###  Natural Language Interface

- Integrates **RAG + Gemini 1.5 Pro** via ChromaDB  
- Supports queries like:  
  - _"What actions did root user take yesterday?"_  
  - _"Show failed login attempts last weekend"_  

###  Streamlit Dashboard

- Upload new log files directly  
- View anomalies by:
  - Severity
  - Source IP
  - Event type
  - Timestamp  
- Issue natural language queries  
- Adjust thresholds and reprocess logs in real time

---
<img width="717" height="483" alt="image" src="https://github.com/user-attachments/assets/9b432cf8-5bd1-478f-81a4-3cee4c50e3a1" />

![Image](https://github.com/user-attachments/assets/3cee56f1-92e5-4732-8a3c-60c9c36b5dbb)

<img width="985" height="617" alt="image" src="https://github.com/user-attachments/assets/e4695142-b3f9-48ce-a3c5-eae8d923f172" />

---

## 🛠️ Technologies Used

| Component                  | Tool / Library         |
|---------------------------|------------------------|
| Log Parsing               | Python, Pandas         |
| Anomaly Detection         | Scikit-learn (IForest) |
| Vector Embeddings         | ChromaDB               |
| Language Model            | Gemini 1.5 Pro         |
| Frontend Dashboard        | Streamlit              |
| Log Summarization         | RAG (semantic search)  |

---

##  Challenges Faced

- Handling varying CloudTrail schemas across services  
- Tuning Isolation Forest to reduce false positives  
- Ensuring low-latency LLM responses  
- Making logs interpretable for non-technical users

---

## Future Improvements

- Real-time streaming (e.g., Kinesis integration)  
-  Role-Based Access Control for dashboards  
-  Support for Azure and GCP logs  
-  Predictive modeling (e.g., breach forecasting)

---

