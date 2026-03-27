"""
URLGuard — Flask Application
Full-stack: Auth, Scanning API, Admin Dashboard, URL submissions.
"""

import os, sys, json, time, hashlib, urllib.parse, csv, io
from datetime import datetime
from pathlib import Path
from functools import wraps

sys.path.insert(0, str(Path(__file__).parent))

from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, make_response, send_file)
import joblib
import numpy as np

from ml.feature_extractor import (
    extract_features, get_feature_names,
    SUSPICIOUS_KEYWORDS, BRAND_KEYWORDS, HIGH_RISK_TLDS, TRUSTED_DOMAINS,
    get_threat_keywords_found
)
from database import (
    init_db, get_user_by_username, get_user_by_id, create_user,
    verify_password, create_session, get_session_user, delete_session,
    update_last_login, log_scan, submit_url as db_submit_url,
    review_submission, get_admin_stats, get_all_users, get_scan_logs,
    get_url_submissions, export_approved_urls, get_db
)

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__,
            template_folder='frontend/templates',
            static_folder='frontend/static')
app.config['SECRET_KEY'] = 'urlguard-secret-2024-xk9'

# ── Init DB ───────────────────────────────────────────────────────────────────
init_db()

# ── Load Model ────────────────────────────────────────────────────────────────
ML_DIR = Path(__file__).parent / 'ml'
try:
    clf    = joblib.load(ML_DIR / 'model.joblib')
    scaler = joblib.load(ML_DIR / 'scaler.joblib')
    with open(ML_DIR / 'model_meta.json') as f:
        meta = json.load(f)
    MODEL_LOADED = True
    print(f"✓ Model loaded | Acc={meta['accuracy']:.3f} | F1={meta['f1_weighted']:.3f}")
except Exception as e:
    MODEL_LOADED = False; clf = scaler = meta = None
    print(f"✗ Model not found: {e}")

CLASS_NAMES  = ['benign', 'phishing', 'defacement', 'malware']
RISK_DISPLAY = {
    'benign':     {'level': 0, 'label': 'Safe',       'color': '#10b981', 'icon': '✓'},
    'phishing':   {'level': 3, 'label': 'Phishing',   'color': '#ef4444', 'icon': '🎣'},
    'defacement': {'level': 2, 'label': 'Defacement', 'color': '#f59e0b', 'icon': '⚡'},
    'malware':    {'level': 3, 'label': 'Malware',    'color': '#dc2626', 'icon': '☠'},
}
session_stats = {'total_scanned': 0, 'threats_found': 0}
session_history = []

# ── Auth helpers ──────────────────────────────────────────────────────────────
def get_current_user():
    token = request.cookies.get('ug_token')
    return get_session_user(token) if token else None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for('login_page', next=request.path))
        return f(*args, **kwargs, user=user)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'admin':
            return redirect(url_for('login_page'))
        return f(*args, **kwargs, user=user)
    return decorated

# ── URL utilities ─────────────────────────────────────────────────────────────
def ensure_scheme(url):
    if not url.startswith(('http://','https://','ftp://')):
        return 'http://' + url
    return url

def normalize_for_model(url):
    for p in ('https://www.','http://www.','https://','http://','ftp://'):
        if url.lower().startswith(p):
            return url[len(p):]
    return url

# ── Rule-based overrides ──────────────────────────────────────────────────────
def rule_based_classify(url, feats):
    try:
        parsed    = urllib.parse.urlparse(ensure_scheme(url))
        hostname  = parsed.netloc.split(':')[0].lower()
        parts     = hostname.split('.')
        domain    = '.'.join(parts[-2:]) if len(parts)>=2 else hostname
        tld       = parts[-1] if parts else ''
        subdomain = '.'.join(parts[:-2]) if len(parts)>2 else ''
    except:
        return None

    if domain in TRUSTED_DOMAINS:
        if not (feats.get('has_ip_address') or feats.get('is_high_risk_tld') or
                feats.get('domain_in_subdomain') or feats.get('num_suspicious_keywords',0)>=2):
            return {'predicted_class':'benign','probabilities':{'benign':96.0,'phishing':2.0,'defacement':1.5,'malware':0.5},'confidence':96.0,'rule':'trusted_domain'}
    if feats.get('has_ip_address'):
        return {'predicted_class':'malware','probabilities':{'benign':5.0,'phishing':15.0,'defacement':5.0,'malware':75.0},'confidence':75.0,'rule':'ip_address'}
    has_brand_sub = any(b in subdomain.lower() for b in BRAND_KEYWORDS)
    if tld in HIGH_RISK_TLDS and has_brand_sub:
        return {'predicted_class':'phishing','probabilities':{'benign':2.0,'phishing':90.0,'defacement':5.0,'malware':3.0},'confidence':90.0,'rule':'high_risk_tld_brand_subdomain'}
    if tld in HIGH_RISK_TLDS and feats.get('num_suspicious_keywords',0)>=2:
        return {'predicted_class':'phishing','probabilities':{'benign':3.0,'phishing':85.0,'defacement':7.0,'malware':5.0},'confidence':85.0,'rule':'high_risk_tld_keywords'}
    return None

def build_threat_details(url, feats, cls, rule):
    details = []
    if rule == 'trusted_domain':
        details.append({'type':'safe','icon':'✓','title':'Verified Trusted Domain','desc':'This domain is on our verified safe-list and passed all checks.'})
        return details
    kw = get_threat_keywords_found(url)
    if kw:
        details.append({'type':'danger' if len(kw)>=2 else 'warning','icon':'🔑','title':'Suspicious Keywords Detected','desc':f'Found: {", ".join(kw[:6])}'})
    if feats.get('has_ip_address'):
        details.append({'type':'danger','icon':'🌐','title':'Raw IP Address Used as Domain','desc':'Legitimate services use domain names, not IP addresses.'})
    if not feats.get('has_https'):
        details.append({'type':'warning','icon':'🔓','title':'No HTTPS Encryption','desc':'Connection is unencrypted — credentials can be intercepted.'})
    if feats.get('is_high_risk_tld'):
        details.append({'type':'danger','icon':'⚠️','title':'High-Risk Domain Extension','desc':'This TLD is frequently associated with phishing/malware.'})
    if feats.get('domain_in_subdomain'):
        details.append({'type':'danger','icon':'🎭','title':'Brand Name in Subdomain','desc':'A trusted brand is mimicked in the subdomain — classic phishing.'})
    if feats.get('url_length',0)>90:
        details.append({'type':'warning','icon':'📏','title':'Abnormally Long URL','desc':f'Length {feats["url_length"]} chars. Long URLs obscure destinations.'})
    if feats.get('has_at_sign'):
        details.append({'type':'danger','icon':'@','title':'@ Symbol in URL','desc':'@ can redirect browsers to a different host entirely.'})
    if feats.get('url_entropy',0)>5.0:
        details.append({'type':'warning','icon':'🔀','title':'High URL Entropy','desc':f'Score {feats["url_entropy"]:.2f} — randomised strings mask malicious destinations.'})
    if not details and cls=='benign':
        details.append({'type':'safe','icon':'✓','title':'No Threats Detected','desc':'This URL passed all security checks and appears to be legitimate.'})
    return details

def run_scan(url_raw):
    start     = time.time()
    url_full  = ensure_scheme(url_raw.strip())
    url_norm  = normalize_for_model(url_full)
    feats     = extract_features(url_norm)
    fv        = np.array(list(feats.values()), dtype=np.float32).reshape(1,-1)
    fs        = scaler.transform(fv)
    override  = rule_based_classify(url_full, feats)
    if override:
        cls, probs, conf, rule = (override['predicted_class'], override['probabilities'],
                                   override['confidence'], override.get('rule'))
    else:
        idx   = int(clf.predict(fs)[0])
        parr  = clf.predict_proba(fs)[0]
        cls   = CLASS_NAMES[idx]
        probs = {CLASS_NAMES[i]: round(float(p)*100,1) for i,p in enumerate(parr)}
        conf  = round(float(max(parr))*100,1)
        rule  = 'ml'
    ri = RISK_DISPLAY[cls]
    risk_score = (int((1-conf/100)*25) if cls=='benign' else
                  int(35+(conf/100)*40) if cls=='defacement' else
                  int(60+(conf/100)*40))
    risk_score = min(100, max(0, risk_score))
    try:
        parsed   = urllib.parse.urlparse(url_full)
        hostname = parsed.netloc.split(':')[0]
    except: hostname = ''
    return {
        'url': url_full, 'original_url': url_raw, 'hostname': hostname,
        'predicted_class': cls, 'confidence': conf, 'risk_score': risk_score,
        'risk_level': ri['level'], 'risk_label': ri['label'],
        'risk_color': ri['color'], 'risk_icon': ri['icon'],
        'probabilities': probs,
        'threat_details': build_threat_details(url_full, feats, cls, rule if rule!='ml' else None),
        'rule_used': rule,
        'features': {
            'url_length': feats.get('url_length',0), 'num_dots': feats.get('num_dots',0),
            'has_https': bool(feats.get('has_https')), 'has_ip_address': bool(feats.get('has_ip_address')),
            'is_high_risk_tld': bool(feats.get('is_high_risk_tld')),
            'num_suspicious_kw': feats.get('num_suspicious_keywords',0),
            'url_entropy': feats.get('url_entropy',0), 'hostname_entropy': feats.get('hostname_entropy',0),
            'num_subdomains': feats.get('num_subdomains',0), 'num_query_params': feats.get('num_query_params',0),
        },
        'scan_time_ms': round((time.time()-start)*1000,1),
        'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'scan_id': hashlib.md5(f"{url_full}{time.time()}".encode()).hexdigest()[:8].upper(),
    }

# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    user = get_current_user()
    return render_template('index.html', user=user, stats=session_stats,
                           model_accuracy=round(meta['accuracy']*100,1) if meta else 0)

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login_page():
    if request.method == 'GET':
        user = get_current_user()
        if user: return redirect('/')
        return render_template('login.html', error=request.args.get('error'),
                               success=request.args.get('success'))
    username = request.form.get('username','').strip()
    password = request.form.get('password','')
    user = get_user_by_username(username)
    if not user or not verify_password(password, user['password']):
        return render_template('login.html', error='Invalid username or password', username=username)
    if not user['is_active']:
        return render_template('login.html', error='Your account has been suspended.', username=username)
    token = create_session(user['id'])
    update_last_login(user['id'])
    next_url = request.args.get('next', '/')
    resp = make_response(redirect(next_url))
    resp.set_cookie('ug_token', token, max_age=7*24*3600, httponly=True, samesite='Lax')
    return resp

@app.route('/register', methods=['GET','POST'])
def register_page():
    if request.method == 'GET':
        user = get_current_user()
        if user: return redirect('/')
        return render_template('register.html')
    username = request.form.get('username','').strip()
    email    = request.form.get('email','').strip()
    password = request.form.get('password','')
    confirm  = request.form.get('confirm_password','')
    if len(username) < 3:
        return render_template('register.html', error='Username must be at least 3 characters', username=username, email=email)
    if len(password) < 8:
        return render_template('register.html', error='Password must be at least 8 characters', username=username, email=email)
    if password != confirm:
        return render_template('register.html', error='Passwords do not match', username=username, email=email)
    result = create_user(username, email, password)
    if 'error' in result:
        return render_template('register.html', error=result['error'], username=username, email=email)
    return redirect(url_for('login_page', success='Account created! Please sign in.'))

@app.route('/logout')
def logout():
    token = request.cookies.get('ug_token')
    if token: delete_session(token)
    resp = make_response(redirect('/login'))
    resp.delete_cookie('ug_token')
    return resp

@app.route('/dashboard')
@login_required
def user_dashboard(user):
    scans = get_scan_logs(limit=50, user_id=user['id'])
    return render_template('dashboard.html', user=user, scans=scans)

# ═════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/scan', methods=['POST'])
def api_scan():
    if not MODEL_LOADED:
        return jsonify({'error': 'Model not loaded. Run: python ml/train_model.py'}), 503
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url:    return jsonify({'error': 'No URL provided'}), 400
    if len(url)>2048: return jsonify({'error': 'URL too long'}), 400
    try:
        result = run_scan(url)
        user   = get_current_user()
        log_scan(user['id'] if user else None, result, request.remote_addr)
        session_stats['total_scanned'] += 1
        if result['predicted_class'] != 'benign':
            session_stats['threats_found'] += 1
        session_history.insert(0, {
            'url': result['url'], 'hostname': result['hostname'],
            'class': result['predicted_class'], 'label': result['risk_label'],
            'color': result['risk_color'], 'icon': result['risk_icon'],
            'time': result['scanned_at'], 'score': result['risk_score'],
        })
        if len(session_history) > 50: session_history.pop()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-bulk', methods=['POST'])
def api_scan_bulk():
    if not MODEL_LOADED: return jsonify({'error':'Model not loaded'}), 503
    data = request.get_json(silent=True) or {}
    urls = [u.strip() for u in (data.get('urls') or []) if u.strip()][:10]
    if not urls: return jsonify({'error':'Provide a list of URLs'}), 400
    user = get_current_user()
    results = []
    for url in urls:
        try:
            r = run_scan(url)
            log_scan(user['id'] if user else None, r, request.remote_addr)
            session_stats['total_scanned'] += 1
            if r['predicted_class'] != 'benign': session_stats['threats_found'] += 1
            results.append(r)
        except Exception as e:
            results.append({'url': url, 'error': str(e)})
    return jsonify({'results': results, 'count': len(results)})

@app.route('/api/submit-url', methods=['POST'])
def api_submit_url():
    user = get_current_user()
    if not user: return jsonify({'error': 'Login required to submit URLs'}), 401
    data  = request.get_json(silent=True) or {}
    url   = (data.get('url') or '').strip()
    label = data.get('suggested_label')
    notes = data.get('notes')
    if not url: return jsonify({'error': 'No URL provided'}), 400
    result = db_submit_url(url, user['id'], label, notes)
    return jsonify(result)

@app.route('/api/stats')
def api_stats(): return jsonify(session_stats)

@app.route('/api/history')
def api_history(): return jsonify({'history': session_history[:20]})

@app.route('/api/health')
def api_health():
    return jsonify({'status':'ok','model_loaded':MODEL_LOADED,
                    'model_accuracy': meta['accuracy'] if meta else None, 'version':'2.0.0'})

# ═════════════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/admin')
@admin_required
def admin_dashboard(user):
    stats        = get_admin_stats()
    recent_scans = get_scan_logs(limit=10)
    all_scans    = get_scan_logs(limit=200)
    users        = get_all_users()
    submissions  = get_url_submissions()
    return render_template('admin.html', user=user, stats=stats,
                           recent_scans=recent_scans, all_scans=all_scans,
                           users=users, submissions=submissions)

@app.route('/admin/review-submission', methods=['POST'])
@admin_required
def admin_review(user):
    data   = request.get_json(silent=True) or {}
    sub_id = data.get('id')
    action = data.get('action')   # 'approved' | 'rejected'
    label  = data.get('label')
    if not sub_id or action not in ('approved','rejected'):
        return jsonify({'error': 'Invalid request'}), 400
    if action == 'approved' and not label:
        return jsonify({'error': 'Label required for approval'}), 400
    review_submission(sub_id, label if action=='approved' else None, action, user['id'])
    return jsonify({'success': True})

@app.route('/admin/toggle-user', methods=['POST'])
@admin_required
def admin_toggle_user(user):
    data   = request.get_json(silent=True) or {}
    uid    = data.get('id')
    action = data.get('action')
    if not uid or action not in ('ban','unban'):
        return jsonify({'error': 'Invalid request'}), 400
    conn = get_db()
    conn.execute("UPDATE users SET is_active=? WHERE id=? AND role!='admin'",
                 (0 if action=='ban' else 1, uid))
    conn.commit(); conn.close()
    return jsonify({'success': True})

@app.route('/admin/approved-count')
@admin_required
def admin_approved_count(user):
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM url_submissions WHERE status='approved'").fetchone()[0]
    conn.close()
    return jsonify({'count': count})

@app.route('/admin/export/urls')
@admin_required
def export_urls(user):
    rows = export_approved_urls()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['url', 'type', 'reviewed_at'])
    for r in rows:
        writer.writerow([r['url'], r['admin_label'], r['reviewed_at']])
    output.seek(0)
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename=urlguard_dataset_{datetime.now().strftime("%Y%m%d")}.csv'
    return resp

@app.route('/admin/export/scans')
@admin_required
def export_scans(user):
    rows   = get_scan_logs(limit=10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id','url','hostname','predicted_class','confidence','risk_score','rule_used','user','ip','scanned_at'])
    for r in rows:
        writer.writerow([r['id'],r['url'],r['hostname'],r['predicted_class'],
                         r['confidence'],r['risk_score'],r['rule_used'],
                         r.get('username',''), r.get('ip_address',''), r['scanned_at']])
    output.seek(0)
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename=urlguard_scans_{datetime.now().strftime("%Y%m%d")}.csv'
    return resp

# ═════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print('\n' + '='*60)
    print('  URLGuard v2.0 — URL Threat Detection Platform')
    print('='*60)
    print('  Scanner  →  http://localhost:5000')
    print('  Login    →  http://localhost:5000/login')
    print('  Admin    →  http://localhost:5000/admin')
    print('  Creds    →  admin / admin123')
    print('='*60 + '\n')
    app.run(debug=True, host='0.0.0.0', port=5000)
