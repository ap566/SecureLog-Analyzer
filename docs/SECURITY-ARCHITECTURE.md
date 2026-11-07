# Security Architecture

## Purpose
Analyze authentication events from a user-supplied CSV and flag repeated failed login patterns.

## Data flow
1. **Source:** CSV exported from an owned or authorized system, or fictional sample data.
2. **Input validation:** Check required columns and supported event types.
3. **Processing:** Normalize event names and count successful and failed login records.
4. **Detection:** Compare failed-attempt counts by source IP and username with a configurable threshold.
5. **Risk labels:** Repeated failures from an IP are labeled HIGH; repeated failures for an account are labeled MEDIUM.
6. **Output:** Dashboard, alert table, and downloadable text report.

## Trust boundaries
The uploaded CSV is untrusted input. The app processes the uploaded data for the current session. Public hosting means users should upload only sanitized, non-sensitive test data.

## Controls
- CSV-only uploader and required-column validation.
- Unsupported event values are excluded.
- No passwords or secrets are requested.
- No scanning, exploitation, account changes, or automatic blocking.

## Limitations
This is an educational batch analyzer, not a production SIEM. Threshold rules can produce false positives and false negatives. Alerts are indicators for investigation, not proof of compromise.

## Architecture flow
CSV log → Upload → Validation → Parsing and counting → Threshold detection → Risk labels → Dashboard/report.
