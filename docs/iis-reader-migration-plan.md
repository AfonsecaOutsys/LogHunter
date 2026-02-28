# IIS Reader Migration Plan (No-Break Strategy)

## Goal
Change the internal IIS log-reading implementation while preserving behavior for all four IIS menu options:

1. 4xx pivot to 2xx/3xx
2. Burst patterns
3. Top bandwidth (sc-bytes)
4. Uploads/payload attempts (cs-bytes)

## Compatibility Contract (must not change)

### Public reader contract
- Keep `IisW3cReader.EnumerateLogFiles(rootDir)` behavior:
  - include `*.log`
  - include `*.log.gz`
  - recursive enumeration
  - deterministic sorted output
- Keep `IisW3cReader.ReadFieldMapAsync(filePath, ct)` behavior:
  - parse `#Fields:` as the column map
  - case-insensitive field lookup
  - return `null` when no field map exists
- Keep `IisW3cReader.ForEachDataLineAsync(filePath, ct, onLine)` behavior:
  - iterate non-header lines only
  - provide `rawLine` for export routines
  - provide token accessor by column index

### Data semantics
- Missing required fields for an option should continue to be handled as a skip/degraded result, not a hard crash.
- Optional fields should continue to be best-effort enrichments.

## Per-option required vs optional fields

### 1) 4xx pivot to 2xx/3xx
- Required:
  - `sc-status`
- Optional:
  - `OriginalIP`, `c-ip` (at least one needed for IP attribution)
  - `cs(User-Agent)` (noise filtering)
  - `cs-uri-stem` (URI ranking in pivot summary)

### 2) Burst patterns
- Required:
  - `date`, `time`, `sc-status`
- Optional:
  - `cs-method`, `cs-uri-stem`, `time-taken`, `cs(User-Agent)`
  - `OriginalIP`, `c-ip` (at least one needed for IP attribution)

### 3) Top bandwidth (sc-bytes)
- Required:
  - `sc-bytes`
- Optional:
  - `sc-status`, `cs-bytes`, `cs-method`, `cs-uri-stem`, `cs(User-Agent)`
  - `OriginalIP`, `c-ip` (at least one needed for IP attribution)

### 4) Uploads/payload attempts (cs-bytes)
- Required:
  - `cs-method`, `cs-bytes`
- Optional:
  - `cs-uri-stem`, `sc-status`, `sc-bytes`, `cs(User-Agent)`
  - `OriginalIP`, `c-ip` (at least one needed for IP attribution)

## Execution approach (phased)

### Phase 0 — Baseline
1. Capture a small IIS fixture set covering:
   - full field set
   - reordered fields
   - missing optional fields
   - missing per-option required fields
   - `.log` and `.log.gz`
2. Record baseline outputs for each of the 4 IIS options (counts + generated files).

### Phase 1 — Reader internals only
1. Refactor internals in `IisW3cReader` without changing signatures.
2. Keep token indexing and raw-line passthrough behavior unchanged.
3. Re-run baseline checks from Phase 0.

### Phase 2 — Optional improvements
1. Introduce structured record adapters only if still contract-compatible.
2. Keep existing option code paths functional behind adapter wrappers.
3. Re-run full baseline checks.

### Phase 3 — Cleanup
1. Remove dead paths only after parity is proven.
2. Keep one rollback tag/commit that restores pre-migration reader.

## Validation checklist (after each change)
- 4xx option still exports 2xx/3xx raw lines for selected IPs.
- Burst option still detects windows and exports selected bucket logs.
- Top bandwidth still ranks IPs and exports CSVs.
- Uploads/payloads still ranks POST/PUT by `cs-bytes` and exports CSVs.
- Missing optional fields do not crash the run.
- Missing required fields cause graceful skip/no-result behavior.

## Rollback criteria
Immediately rollback if any of these regress:
- wrong line exports (raw line altered)
- option produces empty results where baseline had results
- field mapping breaks with reordered `#Fields`
- gzip files no longer parse
