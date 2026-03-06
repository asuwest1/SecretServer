# Backup/Restore Drill Evidence

Date executed: 2026-03-06

Command used:

```powershell
powershell -NoProfile -File infra/scripts/run-backup-restore-drill.ps1 -Runs 3
```

Log file:
- `artifacts/drills/logs/backup_restore_drill_20260306_075614.json`

Results summary:

- Run count: 3
- Integrity check pass: 3/3 (`sourceFingerprint == restoredFingerprint`)
- Max observed RTO: 0.32 seconds
- Max observed RPO: 2.22 seconds

Post-restore integrity validation:

- File fingerprint parity validated for each run.
- Restored payload matched seeded source content in all runs.

RTO/RPO target check from runbook:

- RTO target `< 2 hours`: passed
- RPO target `< 24 hours`: passed
