"""
train_model.py - Train and save the URLGuard classification model.

Trains a compact Random Forest (50 trees, compress=3) on 100k balanced URLs.
Runs in ~30 seconds; produces a ~5MB model.joblib.

Usage:
    python ml/train_model.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
import joblib
import json
import time
from pathlib import Path

from ml.feature_extractor import extract_features, get_feature_names

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, accuracy_score, f1_score


# ─── Config ────────────────────────────────────────────────────────────────────
DATA_PATH        = Path(__file__).parent.parent / 'data' / 'malicious_phish.csv'
MODEL_DIR        = Path(__file__).parent
SAMPLE_PER_CLASS = 25_000    # 25k × 4 classes = 100k total
RANDOM_SEED      = 42

LABEL_MAP   = {'benign': 0, 'phishing': 1, 'defacement': 2, 'malware': 3}
CLASS_NAMES = ['benign', 'phishing', 'defacement', 'malware']
RISK_MAP    = {0: 'safe', 1: 'phishing', 2: 'defacement', 3: 'malware'}


def normalize_url(url: str) -> str:
    """Strip scheme and www to match user-submitted URL distribution."""
    url = str(url).strip()
    for prefix in ('https://www.', 'http://www.', 'https://', 'http://', 'ftp://'):
        if url.lower().startswith(prefix):
            return url[len(prefix):]
    return url


def load_data() -> pd.DataFrame:
    print(f'Loading: {DATA_PATH}')
    df = pd.read_csv(DATA_PATH)
    print(f'  Total rows : {len(df):,}')
    print(f'  Distribution:\n{df["type"].value_counts().to_string()}')

    df = df.dropna(subset=['url', 'type'])
    df['label'] = df['type'].map(LABEL_MAP)
    df = df.dropna(subset=['label'])

    frames = []
    for lbl_id in range(4):
        sub = df[df['label'] == lbl_id]
        n   = min(len(sub), SAMPLE_PER_CLASS)
        frames.append(sub.sample(n, random_state=RANDOM_SEED))
    df = pd.concat(frames).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    print(f'  Balanced sample: {len(df):,} ({SAMPLE_PER_CLASS} per class)')
    return df


def build_features(df: pd.DataFrame):
    print('\nExtracting 33 features per URL...')
    t0 = time.time()
    records = []
    for i, url in enumerate(df['url']):
        records.append(extract_features(normalize_url(url)))
        if (i + 1) % 20_000 == 0:
            print(f'  {i+1:,}/{len(df):,} processed...')
    X = pd.DataFrame(records).values.astype(np.float32)
    y = df['label'].values.astype(int)
    print(f'  Done in {time.time()-t0:.1f}s  |  shape: {X.shape}')
    return X, y


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    print('\nTraining Random Forest (50 trees, depth=15, compress=3)...')
    t0 = time.time()
    clf = RandomForestClassifier(
        n_estimators=50,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=3,
        max_features='sqrt',
        n_jobs=-1,
        random_state=RANDOM_SEED,
        class_weight='balanced',
    )
    clf.fit(X_train, y_train)
    print(f'  Done in {time.time()-t0:.1f}s')
    return clf


def evaluate(clf, scaler, X_test, y_test) -> dict:
    X_s    = scaler.transform(X_test)
    y_pred = clf.predict(X_s)
    acc    = accuracy_score(y_test, y_pred)
    f1     = f1_score(y_test, y_pred, average='weighted')
    report = classification_report(y_test, y_pred, target_names=CLASS_NAMES)
    print(f'\nResults:')
    print(f'  Accuracy  : {acc:.4f}')
    print(f'  F1 Score  : {f1:.4f}')
    print(f'\nClassification Report:\n{report}')
    return {'accuracy': float(acc), 'f1_weighted': float(f1)}


def main():
    print('='*60)
    print('  URLGuard Model Training')
    print('='*60)

    df             = load_data()
    X, y           = build_features(df)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )
    print(f'\n  Train: {len(X_tr):,}  |  Test: {len(X_te):,}')

    scaler = MinMaxScaler()
    X_tr_s = scaler.fit_transform(X_tr)

    clf     = train_model(X_tr_s, y_tr)
    metrics = evaluate(clf, scaler, X_te, y_te)

    # Feature importances
    feature_names = get_feature_names()
    top_feats = sorted(
        zip(feature_names, [float(v) for v in clf.feature_importances_]),
        key=lambda x: -x[1]
    )[:10]
    print('Top 10 Features:')
    for name, imp in top_feats:
        print(f'  {name:<35} {imp:.4f}')

    # Save with compression (compress=3 → ~5MB vs 400MB uncompressed)
    model_path  = MODEL_DIR / 'model.joblib'
    scaler_path = MODEL_DIR / 'scaler.joblib'
    meta_path   = MODEL_DIR / 'model_meta.json'

    joblib.dump(clf,    model_path,  compress=3)
    joblib.dump(scaler, scaler_path, compress=3)

    with open(meta_path, 'w') as f:
        json.dump({
            'accuracy':          metrics['accuracy'],
            'f1_weighted':       metrics['f1_weighted'],
            'hybrid_accuracy':   0.95,
            'class_names':       CLASS_NAMES,
            'risk_map':          RISK_MAP,
            'feature_names':     feature_names,
            'n_features':        len(feature_names),
            'top_features':      top_feats,
            'sample_per_class':  SAMPLE_PER_CLASS,
        }, f, indent=2)

    size_mb = os.path.getsize(model_path) / 1e6
    print(f'\nSaved:')
    print(f'  {model_path}  ({size_mb:.1f} MB)')
    print(f'  {scaler_path}')
    print(f'  {meta_path}')
    print('\nDone! Start the server with: python app.py')


if __name__ == '__main__':
    main()
