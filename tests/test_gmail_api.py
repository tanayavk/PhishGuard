
"""Offline tests for src.ingestion.gmail_api.
Uses mocks; no real Gmail credentials or network access required.
"""

import base64
import pytest
from unittest.mock import MagicMock, Mock, patch

from src.ingestion.gmail_api import fetch_unread_emails, apply_label


class TestFetchUnreadEmails:
    """Test fetch_unread_emails with mocks."""

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_basic_flow_with_mock_credentials(self, mock_load_creds, mock_build):
        mock_load_creds.return_value = MagicMock(valid=True)

        mock_service = MagicMock()
        mock_build.return_value = mock_service

        mock_service.users().messages().list.return_value.execute.return_value = {
            "messages": [{"id": "msg1"}]
        }
        mock_service.users().messages().get.return_value.execute.return_value = {
            "raw": base64.urlsafe_b64encode(
                b"From: user@example.com\r\nSubject: Test\r\n\r\nHello world"
            ).decode()
        }

        emails = fetch_unread_emails(max_count=1)

        assert len(emails) == 1
        assert emails[0].from_header == "user@example.com"
        assert emails[0].subject_header == "Test"

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_empty_inbox(self, mock_load_creds, mock_build):
        mock_load_creds.return_value = MagicMock(valid=True)
        mock_build.return_value = MagicMock()

        mock_build.return_value.users().messages().list.return_value.execute.return_value = {
            "messages": []
        }

        assert fetch_unread_emails(max_count=5) == []

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_parse_email_integration(self, mock_load_creds, mock_build):
        raw = base64.urlsafe_b64encode(
            b"From: user@example.com\r\nSubject: Test Email\r\n\r\n"
            b"Check out http://example.com for more info."
        ).decode()

        mock_load_creds.return_value = MagicMock(valid=True)
        mock_service = MagicMock()
        mock_build.return_value = mock_service

        mock_service.users().messages().list.return_value.execute.return_value = {
            "messages": [{"id": "msg1"}]
        }
        mock_service.users().messages().get.return_value.execute.return_value = {
            "raw": raw
        }

        emails = fetch_unread_emails(max_count=1)

        assert len(emails) == 1
        assert emails[0].from_header == "user@example.com"
        assert emails[0].subject_header == "Test Email"
        assert "http://example.com" in emails[0].urls
        assert emails[0].attachment_hashes == []

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_no_credentials_raises(self, mock_load_creds, mock_build):
        mock_load_creds.side_effect = FileNotFoundError(
            "Gmail credentials file not found"
        )

        with pytest.raises(FileNotFoundError):
            fetch_unread_emails(max_count=1)

    @patch("src.ingestion.gmail_api._build_service")
    def test_no_credentials_path(self, mock_build):
        import src.ingestion.gmail_api as gmail_module

        orig_creds_path = gmail_module.CREDENTIALS_PATH
        orig_token_path = gmail_module.TOKEN_PATH

        try:
            gmail_module.CREDENTIALS_PATH = "/nonexistent/credentials.json"
            gmail_module.TOKEN_PATH = "/nonexistent/token.json"

            with patch(
                "src.ingestion.gmail_api.os.path.exists",
                return_value=False,
            ):
                with pytest.raises(FileNotFoundError):
                    gmail_module._load_credentials()
        finally:
            gmail_module.CREDENTIALS_PATH = orig_creds_path
            gmail_module.TOKEN_PATH = orig_token_path


class TestApplyLabel:
    """Test label management with a mocked Gmail API."""

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_apply_existing_label(self, mock_load_creds, mock_build):
        mock_load_creds.return_value = MagicMock()
        service = MagicMock()
        mock_build.return_value = service

        service.users().labels().list().execute.return_value = {
            "labels": [{"id": "Label_123", "name": "Suspicious"}]
        }

        assert apply_label("msg123", "Suspicious") is True

        service.users().labels().create.assert_not_called()
        service.users().messages().modify.assert_called_once_with(
            userId="me",
            id="msg123",
            body={"addLabelIds": ["Label_123"]},
        )

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_create_missing_label_then_apply(self, mock_load_creds, mock_build):
        mock_load_creds.return_value = MagicMock()
        service = MagicMock()
        mock_build.return_value = service

        labels_api = service.users().labels()
        labels_api.list().execute.return_value = {"labels": []}
        labels_api.create.return_value.execute.return_value = {
            "id": "Label_456",
            "name": "Malicious",
        }

        assert apply_label("msg456", "Malicious") is True

        # Verify the create request's arguments, not the chained execute call.
        labels_api.create.assert_called_once_with(
            userId="me",
            body={
                "name": "Malicious",
                "messageListVisibility": "show",
                "labelListVisibility": "labelShow",
            },
        )
        service.users().messages().modify.assert_called_once_with(
            userId="me",
            id="msg456",
            body={"addLabelIds": ["Label_456"]},
        )

    @patch("src.ingestion.gmail_api._build_service")
    @patch("src.ingestion.gmail_api._load_credentials")
    def test_gmail_api_error_raises_exception(self, mock_load_creds, mock_build):
        from googleapiclient.errors import HttpError

        mock_load_creds.return_value = MagicMock()
        service = MagicMock()
        mock_build.return_value = service

        service.users().labels().list().execute.return_value = {
            "labels": [{"id": "Label_789", "name": "Suspicious"}]
        }

        response = Mock()
        response.status = 403

        service.users().messages().modify().execute.side_effect = HttpError(
            response, b"Permission denied"
        )

        with pytest.raises(Exception, match="Gmail label operation failed"):
            apply_label("msg789", "Suspicious")
