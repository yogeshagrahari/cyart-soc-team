# 04 — Alert Management Practice

> **Tools:** Wazuh · TheHive · Google Sheets  
> **Goal:** Set up alert classification, create dashboards, open incident tickets, and practice escalation.
**Difficulty:** Beginner
**Duration:** 2–3 hours
---

## Sub-sections

- [Wazuh Setup & Dashboard](./Wazuh/README.md)
- [TheHive Incident Ticketing](./TheHive/README.md)
- [Google Sheets Alert Tracker](./Google-Sheets/README.md)

---

## Workflow Overview

```
Raw Alert (Wazuh)
      │
      ▼
Alert Classification (Google Sheets)
      │
      ├── P4/P3 → Document + Close
      │
      ├── P2    → Investigate + Document in TheHive
      │
      └── P1    → IMMEDIATE: Contain + Escalate + TheHive Ticket
```
---

## Lab Completion Checklist

- [ ] Google Sheet alert tracker created with 5+ mock alerts
- [ ] CVSS scoring calculated for each alert
- [ ] Wazuh dashboard created with priority distribution chart
- [ ] TheHive case created with full IOC list
- [ ] Escalation email drafted
- [ ] All screenshots saved to `assets/screenshots/lab01/`

---
