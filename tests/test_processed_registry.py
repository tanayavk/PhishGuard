import pytest

from src.ingestion import processed_registry as registry


@pytest.fixture
def temporary_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(
        registry,
        "DB_PATH",
        tmp_path / "test_registry.db",
    )
    registry.initialize_registry()


def test_first_claim_succeeds(temporary_registry):
    assert registry.claim_message("email-1") is True


def test_duplicate_claim_is_rejected(temporary_registry):
    assert registry.claim_message("email-1") is True
    assert registry.claim_message("email-1") is False


def test_failed_message_can_be_retried(temporary_registry):
    registry.claim_message("email-1")
    registry.mark_failed("email-1")

    assert registry.claim_message("email-1") is True


def test_completed_message_cannot_be_claimed_again(
    temporary_registry,
):
    class Report:
        composite_risk_score = 10.0

        class verdict:
            value = "safe"

        class action:
            value = "allow"

    registry.claim_message("email-1")
    registry.mark_completed("email-1", Report())

    assert registry.is_processed("email-1") is True
    assert registry.claim_message("email-1") is False


def test_unprocessed_message_returns_false(temporary_registry):
    assert registry.is_processed("unknown-email") is False


def test_invalid_message_id(temporary_registry):
    with pytest.raises(ValueError):
        registry.claim_message("")