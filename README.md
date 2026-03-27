# 🚨 Sentinel WebGuard (URLGuard)

> AI-powered web security system for detecting malicious or suspicious websites using machine learning and real-time analysis.

---

## 📌 Overview

Sentinel WebGuard is a full-stack cybersecurity application designed to analyze and detect potentially malicious websites using machine learning techniques.

The system extracts features from URLs and web content, processes them through a trained model, and classifies websites as safe or suspicious. It also provides user and admin dashboards for monitoring and management.

---

## 🚀 Features

* 🔍 AI-based website analysis
* 🧠 Machine Learning model (Anomaly Detection)
* ⚡ Real-time URL scanning
* 👤 User authentication (Login/Register)
* 🛠️ Admin dashboard for monitoring
* 📊 Dashboard with scan results
* 📁 Structured ML pipeline (training + inference)
* 🔐 Secure backend API

---

## 🧠 Machine Learning Pipeline

This project includes a complete ML workflow:

* Feature Extraction (`feature_extractor.py`)
* Data Scaling (`scaler.joblib`)
* Model Training (`train_model.py`)
* Model Storage (`model.joblib`)
* Metadata (`model_meta.json`)

### 🤖 Model Used

* Isolation Forest (Anomaly Detection)

### 📊 Features Extracted

* URL structure
* Length of URL
* Number of special characters
* Domain-related attributes
* Content-based indicators

---

## 🛠️ Tech Stack

### Backend

* Python
* FastAPI / Flask

### Frontend

* HTML, CSS, JavaScript

### Machine Learning

* scikit-learn
* joblib

### Database

* SQLite / Local DB

---

## 📂 Project Structure

```id="u2qv98"
urlguard/
│
├── app.py
├── database.py
├── requirements.txt
│
├── frontend/
│   ├── templates/
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   └── admin.html
│   ├── static/
│   │   ├── css/
│   │   └── js/
│
├── ml/
│   ├── feature_extractor.py
│   ├── train_model.py
│   ├── model.joblib
│   ├── scaler.joblib
│   └── model_meta.json
│
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash id="x3zq1h"
git clone https://github.com/your-username/sentinel-webguard.git
cd sentinel-webguard/urlguard
```

---

### 2️⃣ Install Dependencies

```bash id="6p7g0y"
pip install -r requirements.txt
```

---

### 3️⃣ Run Backend Server

```bash id="r0jv3k"
python app.py
```

---

### 4️⃣ Access the Application

Open in browser:

```id="f8gk2n"
http://localhost:8000
```

---

## 🔐 Authentication

* Users can register and log in
* Role-based system:

  * User → Scan websites and view results
  * Admin → Monitor system activity

---

## 🔍 How It Works

1. User enters a URL
2. System extracts features using ML pipeline
3. Features are scaled and passed to model
4. Model predicts:

   * ✅ Safe
   * ⚠️ Suspicious
5. Results displayed on dashboard

---

## 📊 Example Output

```
URL: example.com
Result: ⚠️ Suspicious
Confidence Score: 0.82
```

---

## 🚧 Future Improvements

* 🔁 Continuous learning with feedback loop
* 🌐 Integration with threat intelligence APIs
* 📷 Visual analysis (screenshot comparison)
* ⚡ Real-time scanning with background workers
* ☁️ Cloud deployment (AWS/GCP)

---

## 🤝 Contributing

Contributions are welcome!
Feel free to fork the repository and submit pull requests.

---

## 📄 License

This project is licensed under the MIT License.

---

## 💼 Author

Sarath.S
GitHub: https://github.com/sarathxxx

---
