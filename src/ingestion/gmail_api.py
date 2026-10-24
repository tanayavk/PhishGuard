
"""Gmail API integration for PHISHGUARD Dev 1."""

from __future__ import annotations

import base64
import os
from typing import List

from src.ingestion.mime_parser import parse_email


# Gmail OAuth configuration
CREDENTIALS_PATH = os.environ.get(
    "GMAIL_CREDENTIALS_PATH", "credentials.json"
)
TOKEN_PATH = os.environ.get("GMAIL_TOKEN_PATH", "token.json")

# Read emails and apply Gmail labels.
GMAIL_SCOPE = ["https://www.googleapis.com/auth/gmail.modify"]


def _load_credentials():
    """Load saved OAuth credentials or start the desktop OAuth flow."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow

    creds = None

    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(
            TOKEN_PATH, GMAIL_SCOPE
        )

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    if not creds or not creds.valid:
        if not os.path.exists(CREDENTIALS_PATH):
            raise FileNotFoundError(
                f"Gmail credentials file not found at: {CREDENTIALS_PATH}. "
                "Place the downloaded OAuth client JSON at this path."
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            CREDENTIALS_PATH, GMAIL_SCOPE
        )
        creds = flow.run_local_server(port=0)

        with open(TOKEN_PATH, "w", encoding="utf-8") as token_file:
            token_file.write(creds.to_json())

    return creds


def _build_service(creds):
    """Build the Gmail API service."""
    from googleapiclient.discovery import build

    return build(
        "gmail",
        "v1",
        credentials=creds,
        cache_discovery=False,
    )


def apply_label(message_id: str, label_name: str) -> bool:
    """Apply a Gmail label, creating it if necessary.

    Args:
        message_id: Gmail message ID.
        label_name: Label name, without a PhishGuard/ prefix.

    Returns:
        True if the label was applied successfully.

    Raises:
        Exception: If the Gmail API operation fails.
    """
    from googleapiclient.errors import HttpError

    creds = _load_credentials()
    service = _build_service(creds)

    try:
        labels_result = (
            service.users()
            .labels()
            .list(userId="me")
            .execute()
        )

        label_id = None
        for label in labels_result.get("labels", []):
            if label.get("name") == label_name:
                label_id = label.get("id")
                break

        if label_id is None:
            created = (
                service.users()
                .labels()
                .create(
                    userId="me",
                    body={
                        "name": label_name,
                        "messageListVisibility": "show",
                        "labelListVisibility": "labelShow",
                    },
                )
                .execute()
            )
            label_id = created.get("id")

        if not label_id:
            raise ValueError(
                f"Could not find or create Gmail label: {label_name}"
            )

        (
            service.users()
            .messages()
            .modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": [label_id]},
            )
            .execute()
        )

        return True

    except HttpError as error:
        raise Exception(
            f"Gmail label operation failed: {error}"
        ) from error
    except Exception as error:
        if str(error).startswith("Gmail label operation failed:"):
            raise
        raise Exception(
            f"Gmail label operation failed: {error}"
        ) from error


def fetch_unread_emails(max_count: int = 5) -> List["ParsedEmailResult"]:
    """Fetch and parse up to max_count unread Gmail messages.

    Args:
        max_count: Maximum number of unread messages to fetch.

    Returns:
        Parsed email results.

    Raises:
        Exception: If the Gmail API request or parsing fails.
    """
    creds = _load_credentials()
    service = _build_service(creds)

    try:
        results = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=["UNREAD"],
                maxResults=max_count,
            )
            .execute()
        )

        messages = results.get("messages", [])
        results_list = []

        for message in messages:
            message_id = message["id"]

            try:
                msg_data = (
                    service.users()
                    .messages()
                    .get(
                        userId="me",
                        id=message_id,
                        format="raw",
                    )
                    .execute()
                )

                raw = msg_data.get("raw")
                if not raw:
                    raise ValueError(
                        f"Message {message_id} has no raw content"
                    )

                # Gmail raw messages use URL-safe Base64 encoding.
                raw_bytes = base64.urlsafe_b64decode(
                    raw + "=" * (-len(raw) % 4)
                )

                parsed = parse_email(raw_bytes, message_id=message_id)
                results_list.append(parsed)

            except Exception as error:
                raise Exception(
                    f"Failed to parse message {message_id}: {error}"
                ) from error

        return results_list

    except Exception as error:
        raise Exception(
            f"Gmail API request failed: {error}"
        ) from error
