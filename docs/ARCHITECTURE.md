# TomcatShield Architecture

## Overview
TomcatShield is a modular Python CLI platform. Each module is independently 
testable and replaceable.

## Module Responsibilities

### cli.py
Entry point. Handles argument parsing, config loading, and orchestrates 
module execution.

### config.py
Loads and validates JSON/YAML configuration files.

### discovery/
- `crawler.py` — Authenticated and unauthenticated crawling
- `inventory.py` — Endpoint inventory management

### tomcat/
- `headerscheck.py` — HTTP security header validation
- `baselinecheck.py` — Default apps, TRACE method, server banner
- `webxmlcheck.py` — Session configuration, error handling

### dast/
- `zaprunner.py` — ZAP daemon lifecycle and scan orchestration
- `parsers.py` — Normalize ZAP output to internal schema

### reporting/
- `jsonreport.py` — Machine-readable JSON output
- `htmlreport.py` — Human-readable HTML output
- `csvexport.py` — Management summary CSV output

### ci/
- `thresholds.py` — Severity threshold enforcement and exit codes

## Data Flow

CLI Input → Config Load → Target Validation
→ Tomcat Hardening Checks → HTTP Evidence
→ ZAP Spider → Crawl Coverage
→ ZAP Active Scan → Raw Alerts
→ Normalizer → Severity Mapping + Deduplication
→ Reporter → JSON + HTML + CSV
→ Threshold Check → Exit Code

## Security Guardrails
- Secrets loaded from environment variables only
- PII redacted from all outputs
- Non-destructive mode enabled by default
- Scope boundaries enforced via include/exclude config