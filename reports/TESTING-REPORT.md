# Testing Report

## Test environment
- Application: SecureLog Analyzer
- Runtime: Python 3 / Streamlit
- Test data: fictional sample_logs.csv
- Test date: fill after actual test
- Tester: fill in

## Test cases

| ID | Test | Expected result | Actual result | Status |
|---|---|---|---|---|
| TC-01 | Upload valid CSV | Data accepted | Fill after running | Pending |
| TC-02 | Missing required column | Validation error displayed | Fill after running | Pending |
| TC-03 | Five failed attempts from one IP at threshold 5 | HIGH alert displayed | Fill after running | Pending |
| TC-04 | Fewer attempts than threshold | No alert for that IP | Fill after running | Pending |
| TC-05 | Unsupported event value | Warning and unsupported event excluded | Fill after running | Pending |
| TC-06 | Download report | Text report downloads | Fill after running | Pending |

## Evidence
Add genuine screenshots of the dashboard, alert table, and downloaded report.

## Findings and conclusion
Record only results reproduced during testing. The supplied sample records are fictional and do not represent a real incident. Do not mark pending tests as passed without evidence.
