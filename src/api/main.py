"""FastAPI backend for PhishGuard."""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from src.ingestion.gmail_runner import (
    run_gmail_analysis,
    GmailRunnerError,
)
from src.reporting import report_store
from src.reporting import audit_logger
import os
import hmac
from fastapi.responses import JSONResponse

app = FastAPI(
    title="PhishGuard API",
    description="Agentic AI-Based Zero-Trust Email Security Gateway",
    version="1.0.0",
)

@app.middleware("http")
async def enforce_api_key(request, call_next):
    path = request.url.path

    # Allow CORS preflight requests.
    if request.method == "OPTIONS":
        return await call_next(request)

    # Keep health checks public.
    if path == "/api/v1/health":
        return await call_next(request)

    # Protect API endpoints.
    if path.startswith("/api/v1/"):
        api_key = os.getenv("PHISHGUARD_API_KEY", "")
        environment = os.getenv(
            "PHISHGUARD_ENV", "development"
        ).lower()

        # Production must have an API key configured.
        if environment == "production" and not api_key:
            return JSONResponse(
                status_code=503,
                content={"detail": "API authentication is not configured."}
            )

        # If a key is configured, validate every protected request.
        if api_key:
            supplied_key = request.headers.get("X-API-Key", "")

            if not hmac.compare_digest(supplied_key, api_key):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key."}
                )

    return await call_next(request)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "PHISHGUARD_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/")
def root():
    return {
        "name": "PhishGuard API",
        "version": "1.0.0",
        "status": "running",
    }


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": "PhishGuard",
    }


@app.post("/api/v1/gmail/scan")
def scan_gmail(
    max_results: int = Query(default=5, ge=1, le=50),
):
    """Fetch unread Gmail messages and analyze them."""

    try:
        result = run_gmail_analysis(max_results=max_results)

        for item in result["results"]:
            report = item.get("report")

            if report is not None:
                item["report"] = report.model_dump(mode="json")

        return result

    except GmailRunnerError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during Gmail scanning.",
        ) from error


@app.get("/api/v1/emails")
def get_emails(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    verdict: str | None = Query(
        default=None,
        pattern="^(safe|suspicious|malicious|inconclusive)$",
    ),
):
    """Retrieve paginated email analysis history."""

    try:
        reports = report_store.list_reports(
            limit=limit,
            offset=offset,
            verdict=verdict,
        )

        return {
            "total": report_store.count_reports(),
            "limit": limit,
            "offset": offset,
            "verdict_filter": verdict,
            "emails": reports,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve email history.",
        ) from error


@app.get("/api/v1/emails/{message_id}")
def get_email_details(message_id: str):
    """Retrieve the complete security report for an email."""

    try:
        report = report_store.get_report(message_id)

        if report is None:
            raise HTTPException(
                status_code=404,
                detail="Email security report not found.",
            )

        return report

    except HTTPException:
        raise

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve email security report.",
        ) from error

@app.get("/api/v1/dashboard/stats")
def dashboard_stats():
    """Return statistics for the PhishGuard dashboard."""

    try:
        return report_store.get_dashboard_stats()

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve dashboard statistics.",
        ) from error

@app.get("/api/v1/audit")
def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    message_id: str | None = None,
):
    try:
        return audit_logger.list_audit_history(
            limit=limit,
            offset=offset,
            message_id=message_id,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve audit logs."
        ) from error


@app.get("/api/v1/audit/{message_id}")
def get_email_audit_logs(
    message_id: str,
    limit: int = Query(default=50, ge=1, le=500),
):
    try:
        records = audit_logger.get_audit_history(
            message_id=message_id,
            limit=limit,
        )

        return {
            "message_id": message_id,
            "total": len(records),
            "audit_logs": records,
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve email audit logs."
        ) from error