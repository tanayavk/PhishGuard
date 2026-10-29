
"""Train and evaluate PhishGuard's lexical URL classifier."""

import csv
import json
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split

from src.detection.feature_extraction import extract_url_features


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = (
    PROJECT_ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
)
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "url_phish_model.joblib"
METRICS_PATH = PROJECT_ROOT / "data" / "models" / "url_phish_metrics.json"

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "is_ip_host",
    "dot_count",
    "hyphen_count",
    "at_count",
    "domain_entropy",
    "suspicious_keyword_count",
]

# Verified dataset mapping: 1 = legitimate, 0 = phishing.
LABEL_LEGITIMATE = 1
LABEL_PHISHING = 0


def load_dataset():
    """Read raw URLs and labels, extracting only runtime-available features."""
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    features = []
    labels = []
    seen = set()
    skipped = 0

    with DATASET_PATH.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        reader = csv.DictReader(file)

        if not {"URL", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("Dataset must contain URL and label columns.")

        for row in reader:
            url = (row.get("URL") or "").strip()
            raw_label = (row.get("label") or "").strip()

            if not url or raw_label not in {"0", "1"}:
                skipped += 1
                continue

            # Avoid exact URL duplicates leaking across the split.
            key = url.casefold()
            if key in seen:
                skipped += 1
                continue
            seen.add(key)

            feature_row = extract_url_features(url)

            # Reject unsupported or malformed URLs instead of training
            # on misleading all-zero feature vectors.
            if not any(feature_row.values()):
                skipped += 1
                continue

            features.append(
                [feature_row[name] for name in FEATURE_NAMES]
            )
            labels.append(int(raw_label))

    if len(features) < 100:
        raise ValueError(
            f"Too few usable records for training: {len(features)}"
        )

    if len(set(labels)) != 2:
        raise ValueError("Training data must contain both label classes.")

    return features, labels, skipped


def main():
    X, y, skipped = load_dataset()

    print(f"Usable unique URLs: {len(X):,}")
    print(f"Skipped rows: {skipped:,}")
    print(f"Legitimate URLs: {y.count(LABEL_LEGITIMATE):,}")
    print(f"Phishing URLs: {y.count(LABEL_PHISHING):,}")
    print(f"Feature count: {len(FEATURE_NAMES)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    print("\nTraining Random Forest...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    metrics = {
        "dataset": "PhiUSIIL Phishing URL Dataset",
        "label_mapping": {
            "0": "phishing",
            "1": "legitimate",
        },
        "feature_names": FEATURE_NAMES,
        "random_state": 42,
        "test_size": 0.20,
        "train_records": len(X_train),
        "test_records": len(X_test),
        "usable_unique_records": len(X),
        "skipped_records": skipped,
        "accuracy": accuracy_score(y_test, predictions),
        "precision_phishing": precision_score(
            y_test, predictions, pos_label=LABEL_PHISHING,
            zero_division=0,
        ),
        "recall_phishing": recall_score(
            y_test, predictions, pos_label=LABEL_PHISHING,
            zero_division=0,
        ),
        "f1_phishing": f1_score(
            y_test, predictions, pos_label=LABEL_PHISHING,
            zero_division=0,
        ),
        "confusion_matrix_labels": [
            "phishing (0)",
            "legitimate (1)",
        ],
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["phishing", "legitimate"],
            output_dict=True,
            zero_division=0,
        ),
    }

    print("\nEvaluation on held-out test set:")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Phishing precision: {metrics['precision_phishing']:.4f}")
    print(f"Phishing recall: {metrics['recall_phishing']:.4f}")
    print(f"Phishing F1: {metrics['f1_phishing']:.4f}")
    print("Confusion matrix (rows=actual, columns=predicted; [0, 1]):")
    print(metrics["confusion_matrix"])

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["phishing", "legitimate"],
            zero_division=0,
        )
    )

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Store metadata alongside the estimator for safe feature-order checks.
    artifact = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "label_mapping": {
            0: "phishing",
            1: "legitimate",
        },
        "dataset": "PhiUSIIL Phishing URL Dataset",
    }

    joblib.dump(artifact, MODEL_PATH)

    METRICS_PATH.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")


if __name__ == "__main__":
    main()
