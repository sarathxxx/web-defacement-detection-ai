# URLGuard v2.0 — AI-Powered Malicious URL Detection Platform

A full-stack web application for detecting **phishing**, **malware**, and **defacement** threats in URLs — with user authentication, admin dashboard, scan logging, and community URL submissions for dataset growth.

---

## Quick Start (3 steps)

```bash
# 1. Install dependencies
pip install flask scikit-learn pandas numpy joblib

# 2. Place malicious_phish.csv in the data/ folder (from archive.zip)
#    Model is pre-trained — skip step 3 if you want to go straight to the website

# 3. Start the server
cd urlguard
python app.py
```

Open **http://localhost:5000**

**Default admin login:** `admin` / `admin123`

---

## Pages & Routes

| URL | Access | Description |
|-----|--------|-------------|
| `/` | Public | Main scanner interface |
| `/login` | Public | Sign in page |
| `/register` | Public | Create new account |
| `/dashboard` | Logged-in | Personal scan history & stats |
| `/admin` | Admin only | Full admin control panel |
| `/logout` | Logged-in | Sign out |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Scan a single URL |
| `/api/scan-bulk` | POST | Scan up to 10 URLs |
| `/api/submit-url` | POST | Submit URL for dataset (auth required) |
| `/api/stats` | GET | Session statistics |
| `/api/history` | GET | Last 20 scan results |
| `/api/health` | GET | Server + model health |
| `/admin/export/urls` | GET | Download approved URLs as CSV |
| `/admin/export/scans` | GET | Download all scan logs as CSV |

---

## Project Structure

```
urlguard/
├── app.py                           ← Flask server (auth + API + admin routes)
├── database.py                      ← SQLite database layer
├── requirements.txt
├── README.md
│
├── ml/
│   ├── feature_extractor.py         ← 33-feature URL analyser
│   ├── train_model.py               ← Retrain script
│   ├── model.joblib                 ← Pre-trained Random Forest (included)
│   ├── scaler.joblib                ← MinMaxScaler (included)
│   └── model_meta.json              ← Model info
│
├── data/
│   └── malicious_phish.csv          ← Place dataset here (from archive.zip)
│
└── frontend/
    ├── index.html                   ← Legacy entry (unused, templates/ used)
    ├── templates/
    │   ├── index.html               ← Main scanner (auth-aware)
    │   ├── login.html               ← Sign in page
    │   ├── register.html            ← Sign up page
    │   ├── dashboard.html           ← User scan history
    │   └── admin.html               ← Admin control panel
    └── static/
        ├── css/
        │   ├── style.css            ← Main design system
        │   ├── auth.css             ← Login/register styles
        │   └── dashboard.css        ← Admin dashboard styles
        └── js/
            └── app.js               ← Scanner frontend logic
```

---

## Database Schema

SQLite database (`urlguard.db`) — auto-created on first run.

### `users`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| username | TEXT UNIQUE | Login name |
| email | TEXT UNIQUE | Email address |
| password | TEXT | SHA-256 hashed |
| role | TEXT | `user` or `admin` |
| is_active | INTEGER | 1=active, 0=banned |
| created_at | TEXT | Registration timestamp |
| last_login | TEXT | Last login timestamp |

### `scan_logs`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | Who scanned (null=guest) |
| url | TEXT | Scanned URL |
| hostname | TEXT | Extracted hostname |
| predicted_class | TEXT | benign/phishing/defacement/malware |
| confidence | REAL | Model confidence % |
| risk_score | INTEGER | 0–100 risk score |
| rule_used | TEXT | Which engine classified it |
| scan_time_ms | REAL | Scan latency |
| features_json | TEXT | JSON feature snapshot |
| ip_address | TEXT | Client IP |
| scanned_at | TEXT | Timestamp |

### `url_submissions`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| url | TEXT | Submitted URL |
| submitted_by | INTEGER FK | User who submitted |
| suggested_label | TEXT | User's guess |
| admin_label | TEXT | Admin's verified label |
| status | TEXT | `pending`/`approved`/`rejected` |
| notes | TEXT | Submission notes |
| submitted_at | TEXT | Submission timestamp |
| reviewed_at | TEXT | Review timestamp |
| reviewed_by | INTEGER FK | Admin who reviewed |

### `sessions`
Cookie-based auth sessions (7-day expiry, auto-managed).

---

## Admin Dashboard Features

### Overview Tab
- Total scans, threats detected, users, pending submissions
- Threat breakdown bar chart (benign / phishing / defacement / malware)
- Most scanned domains list
- Recent scan activity table

### Scan Logs Tab
- Every URL scan ever recorded
- Filter by URL, class, or any text
- Export all logs as CSV

### Users Tab
- All registered users with scan counts
- Ban / unban users (admins protected)

### URL Submissions Tab
- Community-submitted URLs pending review
- Filter by status (pending / approved / rejected)
- Assign label (benign/phishing/defacement/malware) + approve or reject
- Approved URLs are added to the export dataset

### Export Dataset Tab
- Download approved URLs as `urlguard_dataset_YYYYMMDD.csv`
- Download scan logs as `urlguard_scans_YYYYMMDD.csv`
- Model information panel
- Instructions for retraining

---

## Retraining with New Data

When you've accumulated approved URL submissions:

```bash
# 1. Export approved URLs from Admin → Export Dataset tab
#    Downloads: urlguard_dataset_YYYYMMDD.csv

# 2. Merge with original dataset (optional)
python -c "
import pandas as pd
orig = pd.read_csv('data/malicious_phish.csv')
new  = pd.read_csv('urlguard_dataset_YYYYMMDD.csv')
new.columns = ['url', 'type', 'reviewed_at']
new = new[['url', 'type']]
merged = pd.concat([orig, new], ignore_index=True)
merged.to_csv('data/malicious_phish.csv', index=False)
print(f'Merged: {len(merged):,} total URLs')
"

# 3. Retrain
python ml/train_model.py

# 4. Restart server
python app.py
```

---

## ML System

**Hybrid Engine:** 4 deterministic rules + Random Forest

| Rule | Trigger | Result |
|------|---------|--------|
| 1 | Trusted domain (google, amazon, etc.) | Safe (96%) |
| 2 | Raw IP address as hostname | Malware (75%) |
| 3 | High-risk TLD + brand in subdomain | Phishing (90%) |
| 4 | High-risk TLD + 2+ suspicious keywords | Phishing (85%) |
| — | All other URLs | ML prediction |

**Model:** Random Forest (50 trees, depth=15, balanced classes)
**Training data:** 100,000 URLs (25,000 per class, balanced)
**ML accuracy:** 84.5% | **Hybrid accuracy:** ~95%

---

## Security Notes

- Passwords hashed with SHA-256 + salt (upgrade to bcrypt for production)
- Sessions use 64-character random tokens stored in HTTPOnly cookies
- Admin routes protected with `@admin_required` decorator
- Guest scanning allowed (user_id=null in scan_logs)
- For production: use HTTPS, gunicorn, and change SECRET_KEY

---

## Source Files Used

| File | Contribution |
|------|-------------|
| `deep-learning-pytorch-binary-classification.ipynb` | ML pipeline design, training concepts, evaluation metrics |
| `archive.zip` × 2 (malicious_phish.csv) | 651k labelled URLs for model training |
