from collections import Counter

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from scanner import Scanner
from report_generator import ReportGenerator
from utils.logger import log_scan

app = FastAPI(title="VulnSentinel – Web Security Scanner")

templates = Jinja2Templates(directory="templates")


class ScanRequest(BaseModel):
    url: str


@app.post("/scan", response_model=dict)
async def scan_url(req: ScanRequest):
    scanner = Scanner()
    findings = await scanner.scan(req.url)
    report = ReportGenerator(findings)
    findings_dicts = [f.to_dict() for f in findings]

    # log histórico
    log_scan(req.url, report.overall_risk_score(), findings_dicts)

    return {
        "risk_score": report.overall_risk_score(),
        "findings": findings_dicts,
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # primeira visita: só o formulário
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "results": None},
    )


@app.get("/scan-ui", response_class=HTMLResponse)
async def scan_ui(request: Request, url: str):
    scanner = Scanner()
    findings = await scanner.scan(url)
    report = ReportGenerator(findings)
    findings_dicts = [f.to_dict() for f in findings]

    # contagens para gráficos
    severities = [f["severity"] for f in findings_dicts]
    types = [f["vuln_type"] for f in findings_dicts]
    severity_counts = dict(Counter(severities))
    type_counts = dict(Counter(types))

    # log histórico
    log_scan(url, report.overall_risk_score(), findings_dicts)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "results": {
                "url": url,
                "risk_score": report.overall_risk_score(),
                "findings": findings_dicts,
                "severity_counts": severity_counts,
                "type_counts": type_counts,
            },
        },
    )
