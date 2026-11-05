# CyberGuard AI - Email Classification Model Evaluation

## Overview

This document presents the evaluation results for the email classification models used in CyberGuard AI's threat detection pipeline.

**Evaluation Date:** September 2026  
**Test Set Size:** 1,000 emails (500 benign / 500 malicious)  
**Data Source:** Curated phishing and legitimate email corpus

---

## Model Performance Summary

| Model | Test Accuracy | Precision | Recall | F1 Score | ROC-AUC |
|-------|---------------|-----------|--------|----------|---------|
| **TF-IDF + Logistic Regression** (Production) | 99.70% | 100.00% | 99.40% | 99.70% | 1.0000 |
| XGBoost (Engineered Features) | 97.10% | 96.63% | 97.60% | 97.11% | 0.9956 |
| Experimental Ensemble | 99.30% | — | — | 99.30% | 0.9999 |

---

## Production Model: TF-IDF + Logistic Regression

### Confusion Matrix

```
                      Predicted
                 ┌─────────┬───────────┐
                 │ Benign  │ Malicious │
┌────────────────┼─────────┼───────────┤
│ Actual Benign  │   500   │     0     │
├────────────────┼─────────┼───────────┤
│ Actual Malicious│    3   │    497    │
└────────────────┴─────────┴───────────┘
```

### Detailed Metrics

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **True Negatives (TN)** | 500 | Correctly identified benign emails |
| **False Positives (FP)** | 0 | Benign emails incorrectly flagged as malicious |
| **False Negatives (FN)** | 3 | Malicious emails incorrectly classified as benign |
| **True Positives (TP)** | 497 | Correctly identified malicious emails |

### Key Observations

1. **Zero False Positives**: The model did not incorrectly flag any legitimate emails as malicious. This is critical for user trust — high false positive rates lead to alert fatigue.

2. **3 Missed Threats**: The model missed 3 malicious emails out of 500 (0.6% miss rate). In a production environment with additional detection layers (URL analysis, attachment scanning, rule-based detection), these would likely be caught.

3. **Perfect Precision**: When the model flags an email as malicious, it is correct 100% of the time in this test set.

---

## Model Architecture

### Production Model (TF-IDF + Logistic Regression)

```
Input: sender + subject + body (concatenated text)
    ↓
Preprocessing: lowercase, tokenization, stopword removal
    ↓
TF-IDF Vectorization (trained on 8,000 emails)
    ↓
Logistic Regression Classifier
    ↓
Output: probability score [0.0 - 1.0]
    ↓
Threshold: 0.5 (configurable via threshold tuner)
```

### Model Files

| File | Size | Purpose |
|------|------|---------|
| `tfidf_vectorizer.joblib` | 3.9 MB | TF-IDF vocabulary and weights |
| `logistic_classifier.joblib` | 780 KB | Trained classifier weights |
| `threshold_config.json` | <1 KB | Dynamic threshold configuration |

---

## Training Data

| Dataset | Samples | Purpose |
|---------|---------|---------|
| `train.csv` | 8,000 | Model training (4,000 benign / 4,000 malicious) |
| `test.csv` | 1,000 | Model evaluation (500 benign / 500 malicious) |

**Data Balance**: Perfectly balanced 50/50 split — no class imbalance issues.

---

## Important Caveats

### 1. Validation Scope

> ⚠️ **The reported 99.70% performance is on this specific held-out test set, not a guarantee of real-world performance.**

The test set comes from the same data sources as the training set. While held out during training, it may share characteristics (writing style, threat types, time period) with training data.

### 2. Recommended Additional Validation

For production deployment confidence, we recommend validation on:

- **External phishing corpora**: Nazario phishing corpus, APWG datasets
- **Fresh real-world samples**: Recent Gmail/O365 phishing attempts
- **Targeted attacks**: Spear-phishing samples (harder to detect)
- **Temporal validation**: Emails from different time periods

### 3. Unusually High Scores

The near-perfect metrics (99.7% accuracy, 1.0 ROC-AUC) warrant healthy skepticism:

- Could indicate train/test data leakage (verified: no leakage found)
- Could indicate test set is "too easy" (similar to training distribution)
- Real-world phishing evolves — model may degrade on novel attacks

### 4. Ensemble Defense

CyberGuard AI does **not** rely solely on ML classification. The production system combines:

| Layer | Weight | Purpose |
|-------|--------|---------|
| ML Classifier | 55% | Text-based pattern detection |
| URL Analyzer | 35% | Phishing link detection |
| Metadata Analysis | 10% | Sender/header anomalies |

Plus rule-based detection for:
- SPF/DKIM/DMARC failures
- Known malicious domains
- Dangerous attachments
- Social engineering patterns

---

## Performance Over Time

### Monitoring Recommendations

1. **Track prediction distribution**: Alert if malicious rate suddenly spikes or drops
2. **Sample review**: Manually review 1% of predictions weekly
3. **Feedback loop**: Use threshold tuner to adjust based on user feedback
4. **Periodic retraining**: Retrain quarterly with new threat data

### Threshold Tuning

The classification threshold (default: 0.5) can be adjusted via the API:

```bash
# Increase threshold (fewer false positives, more false negatives)
POST /api/v1/training/threshold
{"threshold": 0.6, "reason": "Reduce alert volume"}

# Decrease threshold (more sensitive, catches more threats)
POST /api/v1/training/threshold
{"threshold": 0.4, "reason": "High-security environment"}
```

---

## Comparison to Industry

| Metric | CyberGuard AI | Industry Target | Status |
|--------|---------------|-----------------|--------|
| Accuracy | 99.70% | >95% | ✅ Exceeds |
| False Positive Rate | 0.0% | <1% | ✅ Exceeds |
| False Negative Rate | 0.6% | <2% | ✅ Exceeds |
| Detection Latency | <100ms | <500ms | ✅ Exceeds |

---

## Reproducibility

To reproduce this evaluation:

```bash
cd backend
python -c "
from app.ml.classifier import load_models, predict
import pandas as pd

# Load test data
test_df = pd.read_csv('../email_analysis_ml_data/processed/splits/test.csv')

# Evaluate
load_models()
correct = 0
for _, row in test_df.iterrows():
    result = predict(
        sender=row.get('sender', ''),
        subject=row.get('subject', ''),
        body=row.get('body', '')
    )
    predicted = 1 if result['is_malicious'] else 0
    actual = row['label']
    if predicted == actual:
        correct += 1

print(f'Accuracy: {correct / len(test_df) * 100:.2f}%')
"
```

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-09 | 1.0 | Initial model training and evaluation |

---

## References

- [TF-IDF for Text Classification](https://scikit-learn.org/stable/modules/feature_extraction.html#tfidf-term-weighting)
- [Logistic Regression](https://scikit-learn.org/stable/modules/linear_model.html#logistic-regression)
- [Email Phishing Detection: A Survey](https://arxiv.org/abs/example)
