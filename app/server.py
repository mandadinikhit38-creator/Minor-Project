from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    load_dotenv = None
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.scanner import (
    ScanError,
    ScanRateLimiter,
    check_ip_reputation,
    check_ssl,
    expand_link,
    lookup_dns,
    lookup_website_age,
    scan_url,
)

ROOT = Path(__file__).resolve().parent.parent
if load_dotenv is not None:
    load_dotenv(ROOT / ".env")

app = FastAPI(title="PhishLens", description="URL phishing risk analysis", version="1.0.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
limiter = ScanRateLimiter(
    limit=int(os.getenv("SCAN_RATE_LIMIT", "10")),
    window_seconds=int(os.getenv("SCAN_RATE_WINDOW_SECONDS", "60")),
)


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class ToolRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/tools", include_in_schema=False)
def tools_page() -> FileResponse:
    return FileResponse(ROOT / "static" / "tools.html")


@app.get("/about", include_in_schema=False)
def about_page() -> FileResponse:
    return FileResponse(ROOT / "static" / "about.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
def scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(status_code=429, detail="Too many scans. Please wait a minute and try again.")
    try:
        return scan_url(payload.url)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/tools/{tool_name}")
def run_tool(tool_name: str, payload: ToolRequest, request: Request) -> dict[str, Any]:
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(status_code=429, detail="Too many scans. Please wait a minute and try again.")
    tools = {
        "ssl": check_ssl,
        "dns": lookup_dns,
        "expand": expand_link,
        "age": lookup_website_age,
        "ip-reputation": check_ip_reputation,
        "scam-check": scan_url,
    }
    tool = tools.get(tool_name)
    if tool is None:
        raise HTTPException(status_code=404, detail="Unknown PhishLens tool.")
    try:
        return tool(payload.value)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/samples")
def samples() -> dict[str, list[dict[str, str]]]:
    return {"samples": [
        {"url": "https://www.wikipedia.org/", "label": "Well-known site"},
        {"url": "secure-login.verify-account.example.com", "label": "Suspicious URL pattern"},
        {"url": "paypal-account-update.example.com/signin", "label": "Brand impersonation pattern"},
    ]}
