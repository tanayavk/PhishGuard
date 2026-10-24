from email.message import EmailMessage
from io import BytesIO

import qrcode

from src.ingestion.mime_parser import parse_email


def test_mime_parser_extracts_qr_url_from_image_attachment():
    target_url = "https://qr-example.com"

    image = qrcode.make(target_url)
    image_bytes = BytesIO()
    image.save(image_bytes, format="PNG")

    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "QR integration test"
    msg.set_content("Please review the attached image.")

    msg.add_attachment(
        image_bytes.getvalue(),
        maintype="image",
        subtype="png",
        filename="test-qr.png",
    )

    result = parse_email(msg.as_bytes())

    assert target_url in result.qr_urls
