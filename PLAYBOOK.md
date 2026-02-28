# LogHunter Playbook (Confluence-Ready Framework)

> Purpose: This document is a **detailed framework** you can copy into Confluence and incrementally enrich with screenshots, incident examples, and team-specific SOP details.

---

## Document control

- **Owner:** `<team / person>`
- **Last updated:** `<yyyy-mm-dd>`
- **Version:** `<v1.0>`
- **Audience:** SOC analysts, SREs, incident responders, platform engineers
- **Scope:** Log triage with LogHunter for ALB, IIS, OutSystems Platform, and IP reputation enrichment

### Change log

| Date | Author | Change |
|---|---|---|
| `<yyyy-mm-dd>` | `<name>` | Initial draft |
| `<yyyy-mm-dd>` | `<name>` | Added screenshots and examples |

---

## 1) Why use this playbook

Use this playbook when you need fast, consistent answers to questions like:
- Which IPs are driving suspicious traffic?
- Is an IIS error storm actually probing/scanning?
- Are suspicious requests tied to authenticated users?
- Is external IP reputation corroborating the suspicion?

**Outcome:** repeatable investigations that generate evidence packs colleagues can trust and hand off.

---

## 2) Tooling prerequisites

### Runtime prerequisites
- Windows x64 runtime environment (published single-file EXE target).
- Optional for source execution: .NET 8 SDK.
- For ALB log pulls: AWS CLI installed and authenticated with S3 read permissions.
- Optional: AbuseIPDB API key for enrichment.

### Data prerequisites
- ALB logs available in S3 OR downloaded into workspace.
- IIS W3C logs exported for target time window.
- OutSystems Platform exports (CSV/XLSX) when doing platform/authenticated activity checks.

### Access prerequisites (team guidance)
- Incident/ticket ID assigned.
- Read access to source log repositories/storage.
- Permission to process potentially sensitive log data.

---

## 3) Standard workspace convention (recommended)

Use one workspace per incident.

**Example structure (suggested):**

```text
C:\Investigations\INC-12345\
  input\
    alb\
    iis\
    platform\
  notes\
  output\
```

### Naming standard
- Workspace root: `INC-<ticket-number>`
- Output archive: `INC-<ticket-number>_LogHunter_<yyyy-mm-dd>.zip`

### Data handling rules
- Keep original logs immutable.
- Treat exported artifacts as evidence.
- Do not overwrite prior exports; append timestamped outputs.

---

## 4) How to launch LogHunter

### Published executable
```bash
LogHunter.exe
```

### From source
```bash
dotnet run --project LogHunter/LogHunter.csproj
```

### Useful flags
```bash
LogHunter.exe --help
LogHunter.exe --version
LogHunter.exe --root <workspace-path>
```

**Operator note:** always set `--root` for incident isolation when possible.

---

## 5) Investigation framework (primary workflow)

This is the default sequence for most incidents.

## Phase A — Intake and scoping

### Objective
Define what happened, when, and where before scanning broadly.

### Checklist
- Confirm incident window (UTC/local) and affected systems.
- Decide which log domains are in scope: ALB / IIS / Platform.
- Launch LogHunter in a dedicated workspace.

### Evidence to capture
- Ticket ID and incident summary.
- Time window and source systems.

### Screenshot placeholder
- `[Add screenshot: Main menu with workspace shown]`

---

## Phase B — Rapid source identification

### Objective
Find top suspicious actors quickly.

### Menu paths to run
- `ALB -> Top IPs for endpoint/path fragment`
- `ALB -> Top 50 IPs overall`
- `IIS -> 4xx -> pick suspicious IPs -> pivot to 2xx/3xx`
- `Platform -> Suspicious requests: extract IPs`

### Analyst interpretation guidance
- Prioritize IPs that appear across multiple views (route + overall + errors).
- Prefer route-normalized outputs (no-query variants) to avoid parameter noise.
- Save selections when prompted for downstream steps.

### Evidence to capture
- Top IP tables (top 10/20).
- Initial suspicious set rationale (why selected).

### Screenshot placeholders
- `[Add screenshot: ALB top IPs for endpoint output]`
- `[Add screenshot: IIS 4xx suspicious selection screen]`

---

## Phase C — Behavior and impact characterization

### Objective
Determine whether activity is bursty, persistent, blocked, or payload-heavy.

### Menu paths to run
- `ALB -> Requests per IP per 5 minutes (chart)`
- `ALB -> WAF blocked summary + top blocked requests`
- `ALB -> WAF blocks over time (per minute) (chart)`
- `IIS -> Burst patterns`
- `IIS -> Top bandwidth IPs and URIs (sc-bytes)`
- `IIS -> Uploads and payload attempts (cs-bytes)`

### Analyst interpretation guidance
- Bursty + high-volume + repeated route targeting = likely automated abuse.
- WAF-blocked concentration on specific URI patterns may indicate exploit attempts.
- Large `cs-bytes` on write methods (POST/PUT) can indicate upload/payload attempts.

### Evidence to capture
- Chart artifacts (time series for request spikes / WAF blocks).
- Burst IP set and payload-heavy endpoints.

### Screenshot placeholders
- `[Add screenshot: ALB requests per IP chart]`
- `[Add screenshot: WAF blocked summary table]`
- `[Add screenshot: IIS burst pattern output]`

---

## Phase D — Account-risk validation (Platform)

### Objective
Check if suspicious sources map to authenticated activity.

### Menu paths to run
- `Platform -> Suspicious IPs: authenticated activity check`

### Analyst interpretation guidance
- `UserId != 0` activity from suspicious IPs may raise account-compromise concern.
- Distinguish between shared/proxy IP patterns and targeted account activity.

### Evidence to capture
- Authenticated-hit counts per suspicious IP.
- Any correlated users/sessions if available in exports.

### Screenshot placeholder
- `[Add screenshot: Platform authenticated activity results]`

---

## Phase E — External enrichment and confidence scoring

### Objective
Validate internal suspicion with reputation context.

### Menu paths to run
- `IP reputation (AbuseIPDB)` from:
  - output CSV
  - IIS burst session IPs
  - Platform suspicious cache IPs
- `Set or update API key (writes config)` (if needed)

### Analyst interpretation guidance
- Reputation is supporting evidence, not sole ground truth.
- Combine internal behavior + external reputation for containment decisions.

### Evidence to capture
- Enriched CSV export.
- Final confidence tier (High / Medium / Low) per top offender.

### Screenshot placeholder
- `[Add screenshot: AbuseIPDB results table with score bands]`

---

## Phase F — Export, handoff, and closure

### Objective
Deliver a reusable evidence package and clear recommendation.

### Menu paths to run
- `Main -> Saved selections`
- `Main -> Export saved selections`

### Required handoff artifacts
- Summary narrative (what happened, impact, confidence).
- Top offending IPs and top targeted routes.
- ALB/IIS/Platform key evidence files from `/output`.
- Reputation enrichment CSV.
- Recommended containment actions.

### Screenshot placeholder
- `[Add screenshot: Export saved selections completion message]`

---

## 6) Scenario playbooks (quick-use variants)

## Scenario 1 — ALB endpoint abuse spike

1. Run `Top IPs for endpoint/path fragment` on affected route.
2. Run `Top 50 IPs by URI (no query)` for route grouping.
3. Run request and WAF timeline charts.
4. Reputation-check top offenders.
5. Export and attach artifacts to incident.

**Recommended screenshot set:**
- endpoint top IPs
- request timeline chart
- WAF summary

## Scenario 2 — IIS 4xx storm / possible probing

1. Run 4xx pivot workflow and pick suspicious IPs.
2. Run burst patterns; save burst IP set.
3. Run bandwidth and payload-intel options.
4. Check burst set in AbuseIPDB.
5. Export evidence and recommend controls.

**Recommended screenshot set:**
- 4xx suspicious pick list
- burst detection output
- payload intel top endpoints

## Scenario 3 — Platform suspicious traffic + auth risk

1. Extract suspicious IPs from Platform exports.
2. Run authenticated activity check.
3. Enrich suspicious set in AbuseIPDB.
4. Produce account-risk narrative + containment recommendation.

**Recommended screenshot set:**
- suspicious extraction summary
- authenticated check results
- final enrichment table

---

## 7) Quality and consistency checklist (for colleagues)

Before publishing findings, confirm:
- [ ] Workspace tied to ticket ID.
- [ ] Time window documented.
- [ ] Suspicious set backed by at least 2 evidence views.
- [ ] At least one timeline artifact included when relevant.
- [ ] Reputation enrichment included (or reason omitted).
- [ ] All exported files stored in ticket evidence location.
- [ ] Recommendations clearly state confidence and blast radius.

---

## 8) Confluence conversion template

Copy this into Confluence and replace placeholders.

## `<Incident Title>`

### 1. Context
- Ticket: `<INC-####>`
- Time window: `<UTC range>`
- Systems: `<ALB/IIS/Platform>`

### 2. Investigation workflow used
- Phases executed: `<A-F>`
- Any deviations: `<why>`

### 3. Findings
- Top IPs: `<list>`
- Top routes: `<list>`
- Behavior: `<bursty/persistent/waf-blocked/payload-heavy>`
- Auth activity overlap: `<yes/no + details>`
- Reputation summary: `<high/medium/low concern>`

### 4. Evidence
- `<Attach CSV/HTML outputs>`
- `<Insert screenshots from placeholders>`

### 5. Recommendations
- Immediate: `<block/rate-limit/waf rule changes>`
- Follow-up: `<deeper hunt/credential resets/monitoring updates>`

### 6. Confidence and caveats
- Confidence: `<High/Medium/Low>`
- Caveats: `<data gaps, logging blind spots>`

---

## 9) Appendix — command cheat sheet

```bash
# run from source
 dotnet run --project LogHunter/LogHunter.csproj

# help/version
 LogHunter.exe --help
 LogHunter.exe --version

# isolate an incident workspace
 LogHunter.exe --root C:\Investigations\INC-12345
```
