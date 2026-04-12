# XWA-SEC Development Roadmap

This document tracks the strategic steps required to evolve the XWA-SEC application into a full-scale web cybersecurity suite. 
This file is formatted to be synced automatically with GitHub Issues using the `xgh` roadmap standard.

## Infrastructure & Core Initialization <!-- phase:infrastructure -->

- [x] Dockerize frontend (Angular) and backend (FastAPI) environments
- [x] Integrate PostgreSQL and Redis architectures for persistence
- [x] Implement the Nothing Design System UI tokens and layout
- [x] Configure Docker-compose for rapid local development (HMR Support)

## Real-time Scanning Engine <!-- phase:real-time-engine -->

- [x] Scaffold SQLAlchemy models for Scans and Findings
- [x] Create WebSocket endpoints for real-time console streaming
- [x] Integrate native Nmap execution as an asynchronous Python subprocess
- [x] Build the "Nothing Terminal" component in Angular to render WebSocket streams

## Deep Vulnerability Analysis Integration <!-- phase:vuln-analysis -->

- [ ] Integrate SQLMap subprocess runner for automated SQL Injection vulnerability checks
- [ ] Connect Nuclei vulnerability scanner templates to expand the footprint engine
- [ ] Implement robust `stdout` parsing heuristics for automated Finding severity classification
- [ ] Establish asynchronous fuzzing for directory and file brute-forcing

## Headless Reconnaissance & Crawling <!-- phase:recon-crawler -->

- [ ] Add headless browser nodes (Playwright) to execute JavaScript-heavy reconnaissance
- [ ] Intercept, capture, and analyze XHR/Fetch network requests dynamically
- [ ] Implement visual screenshot capture module for successfully resolved domains
- [ ] Automate Site Topology mapping through recursive spider crawling

## Security, Auth & Production Hardening <!-- phase:production-hardening -->

- [ ] Wrap FastAPI backend routes with JWT Authentication middleware
- [ ] Add RBAC (Role-Based Access Control) to restrict scan actions by user level
- [ ] Implement Redis-based rate limiting to prevent application scan flooding
- [ ] Setup scheduled recurrent scans via Celery Beat tasks
- [ ] Develop exportable Executive Reports (PDF and CSV format) for compiled findings
