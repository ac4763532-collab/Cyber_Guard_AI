import html
import re
from email.header import decode_header, make_header
from pathlib import Path
from typing import Any

import joblib
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Model paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.joblib"
CLASSIFIER_PATH = MODEL_DIR / "logistic_classifier.joblib"

DEFAULT_THRESHOLD = 0.5  # Fallback if tuner unavailable


# ---------------------------------------------------------------------------
# Model state
# ---------------------------------------------------------------------------

_vectorizer = None
_classifier = None
_model_loaded = False
_model_error: str | None = None


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

def decode_mime_text(text: Any) -> str:
    """Decode MIME-encoded email headers."""
    if not text:
        return ""

    try:
        return str(make_header(decode_header(str(text))))
    except Exception:
        return str(text)


def normalize_text(text: Any) -> str:
    """Normalize text while preserving multilingual characters."""
    if not text:
        return ""

    text = html.unescape(str(text))
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def clean_email_body(body: Any) -> str:
    """Remove HTML/CSS/script noise while preserving visible text and URLs."""
    if not body:
        return ""

    body = html.unescape(str(body))

    # Remove script blocks.
    body = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove style blocks.
    body = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Extract URLs before removing HTML.
    urls = re.findall(
        r"https?://[^\s<>\"]+",
        body,
        flags=re.IGNORECASE,
    )

    # Extract visible text from HTML.
    soup = BeautifulSoup(body, "html.parser")
    text = soup.get_text(" ", strip=True)

    # Normalize whitespace.
    text = re.sub(r"\s+", " ", text)

    # Preserve URLs as explicit tokens.
    if urls:
        text += " " + " ".join(urls)

    return text.strip()


def preprocess_email(
    sender: str = "",
    subject: str = "",
    body: str = "",
) -> str:
    """
    Create the exact text representation expected by the trained model.
    """

    sender = normalize_text(sender)

    # Decode MIME subject.
    subject = decode_mime_text(subject)

    # Clean HTML body.
    body = clean_email_body(body)

    # IMPORTANT:
    # This format matches the training preprocessing.
    combined = (
        "SENDER " + sender +
        " SUBJECT " + subject +
        " BODY " + body
    )

    return combined.strip()


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def load_models() -> bool:
    """
    Load TF-IDF vectorizer and Logistic Regression classifier.

    Models are loaded once and kept in memory.
    """

    global _vectorizer
    global _classifier
    global _model_loaded
    global _model_error

    if _model_loaded:
        return True

    try:
        if not VECTORIZER_PATH.exists():
            raise FileNotFoundError(
                f"TF-IDF vectorizer not found: {VECTORIZER_PATH}"
            )

        if not CLASSIFIER_PATH.exists():
            raise FileNotFoundError(
                f"Logistic Regression model not found: {CLASSIFIER_PATH}"
            )

        _vectorizer = joblib.load(VECTORIZER_PATH)
        _classifier = joblib.load(CLASSIFIER_PATH)

        _model_loaded = True
        _model_error = None

        return True

    except Exception as exc:
        _vectorizer = None
        _classifier = None
        _model_loaded = False
        _model_error = str(exc)

        return False


# ---------------------------------------------------------------------------
# Threshold management
# ---------------------------------------------------------------------------

def get_threshold(sender: str = "") -> float:
    """
    Get the classification threshold, using feedback-tuned value if available.

    Args:
        sender: Sender email for domain-specific threshold lookup

    Returns:
        Threshold value (0.0 to 1.0)
    """
    try:
        from app.ml.threshold_tuner import get_threshold_tuner
        tuner = get_threshold_tuner()

        # Extract domain for domain-specific thresholds
        domain = None
        if sender and "@" in sender:
            domain = sender.split("@")[-1].lower()

        return tuner.get_threshold(domain)
    except Exception:
        # Fallback to default if tuner unavailable
        return DEFAULT_THRESHOLD


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict(
    sender: str = "",
    subject: str = "",
    body: str = "",
) -> dict[str, Any]:
    """
    Predict whether an email is malicious.

    Uses feedback-tuned threshold when available.

    Returns:
        {
            "is_malicious": bool,
            "probability": float,
            "confidence": float,
            "threshold": float,
            "model": str,
            "model_loaded": bool
        }
    """

    # Get dynamic threshold (feedback-tuned or default)
    threshold = get_threshold(sender)

    if not load_models():
        return {
            "is_malicious": False,
            "probability": 0.0,
            "confidence": 0.0,
            "threshold": threshold,
            "model": "tfidf_logistic_regression",
            "model_loaded": False,
            "error": _model_error,
        }

    text = preprocess_email(
        sender=sender,
        subject=subject,
        body=body,
    )

    vector = _vectorizer.transform([text])

    probability = float(
        _classifier.predict_proba(vector)[0][1]
    )

    is_malicious = probability >= threshold

    confidence = (
        probability
        if is_malicious
        else 1.0 - probability
    )

    return {
        "is_malicious": is_malicious,
        "probability": round(probability, 6),
        "confidence": round(confidence, 6),
        "threshold": threshold,
        "model": "tfidf_logistic_regression",
        "model_loaded": True,
    }


# ---------------------------------------------------------------------------
# Model status
# ---------------------------------------------------------------------------

def get_model_status() -> dict[str, Any]:
    """Return the current ML model status."""

    current_threshold = get_threshold()

    return {
        "loaded": _model_loaded,
        "model": "tfidf_logistic_regression",
        "threshold": current_threshold,
        "default_threshold": DEFAULT_THRESHOLD,
        "vectorizer_path": str(VECTORIZER_PATH),
        "classifier_path": str(CLASSIFIER_PATH),
        "error": _model_error,
    }
