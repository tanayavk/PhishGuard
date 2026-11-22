from src.ingestion.gmail_client import fetch_unread_emails

emails = fetch_unread_emails(max_results=5)

print(f"\nFetched {len(emails)} unread emails\n")

for email in emails:
    print("-" * 50)
    print("Message ID:", email.message_id)
    print("Sender:", email.sender)
    print("Subject:", email.subject)
    print("URLs:", email.urls)
    print("QR URLs:", email.qr_urls)
    print("Attachments:", email.attachment_hashes)