from src.ingestion.gmail_client import fetch_unread_emails
from src.orchestrator.pipeline import analyze_artifacts

emails = fetch_unread_emails(max_results=5)

for email in emails:
    print("\nAnalysing:", email.subject)

    report = analyze_artifacts(email)

    print(report.model_dump_json(indent=2))