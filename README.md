# 🛡️ SOC Alert Prioritization Engine

### Security Operations Center (SOC) Dashboard

A Python-based Security Operations Center (SOC) Alert Prioritization Engine designed to help security analysts monitor, analyze, prioritize, and investigate security alerts using risk scoring and threat intelligence.

## 📌 Project Overview

Security Operations Centers receive numerous security alerts every day. Manually analyzing each alert can be time-consuming and makes it difficult to identify high-priority threats.

This project provides a centralized dashboard that helps analysts identify potentially suspicious activities, analyze IP reputation, prioritize security alerts, and manage the investigation workflow.

## 🚀 Key Features

- **Security Alert Monitoring:** Centralized dashboard to monitor security alerts.
- **Duplicate Alert Detection:** Identifies and groups duplicate security alerts.
- **IP Reputation Analysis:** Integrates AbuseIPDB to retrieve IP reputation information.
- **Risk Scoring:** Calculates risk scores using internal scoring, IP reputation, and alert occurrences.
- **Risk Classification:** Classifies alerts into Low, Medium, High, and Critical categories.
- **Alert Investigation:** Provides detailed investigation information for individual alerts.
- **Investigation Recommendations:** Displays investigation reasons and recommended actions.
- **Analyst Workflow Management:** Manage alerts using New, Investigating, and Resolved statuses.
- **Search and Filtering:** Search alerts by name or IP address and filter by risk level.
- **SOC Analyst Performance Dashboard:** Displays pending, investigating, and resolved alerts along with investigation progress.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application framework |
| SQLite | Database management |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Search and filtering |
| AbuseIPDB API | IP reputation analysis |

## ⚙️ Project Architecture

```text
SOC-Alert-Prioritization/
│
├── app.py
├── database.py
├── ip_reputation.py
├── risk_engine.py
├── requirements.txt
├── .gitignore
│
├── templates/
│   ├── index.html
│   └── investigation.html
│
└── static/
    └── style.css
```

## 🔍 How It Works

1. Security alerts are stored in an SQLite database.
2. Duplicate alerts are grouped to reduce repeated entries.
3. Source IP addresses are checked using AbuseIPDB threat intelligence.
4. The risk engine calculates a risk score for each alert.
5. Alerts are classified into Low, Medium, High, or Critical risk levels.
6. Analysts can investigate alerts and view recommended actions.
7. Analysts update the workflow status as New, Investigating, or Resolved.
8. The performance dashboard displays investigation progress.

## 📊 Risk Scoring

The project uses a rule-based risk scoring model that considers:

- Internal risk score.
- IP abuse confidence score.
- Duplicate alert occurrences.

The final risk score is used to classify alerts into four categories:

| Risk Score | Classification |
|---|---|
| 0–29 | Low |
| 30–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

*Note: These thresholds are defined by this project's scoring model and are not an industry-standard scoring framework.*

## 💻 Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/SOC-Alert-Prioritization-Engine.git
```

### 2. Navigate to the Project Folder

```bash
cd SOC-Alert-Prioritization-Engine
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure AbuseIPDB API

Create a `.env` file in the project directory:

```env
ABUSEIPDB_API_KEY=your_api_key_here
```

Replace the placeholder with your own API key.

Never upload your `.env` file or API key to GitHub.

### 7. Run the Application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000/
```

## 🎯 Project Objectives

- Improve security alert monitoring.
- Reduce duplicate alert noise.
- Prioritize potentially dangerous alerts.
- Support faster security investigations.
- Provide better visibility into analyst workflow.

## 🔮 Future Scope

- Alert timeline tracking.
- Advanced threat intelligence integration.
- Automated alert correlation.
- Downloadable incident investigation reports.
- Advanced security analytics and visualizations.
*******************************************************************************************************
