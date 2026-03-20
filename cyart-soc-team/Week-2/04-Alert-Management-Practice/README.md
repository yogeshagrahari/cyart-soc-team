# 04 — Alert Management Practice

> **Tools:** Wazuh · TheHive · Google Sheets  
> **Goal:** Set up alert classification, create dashboards, open incident tickets, and practice escalation.

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
