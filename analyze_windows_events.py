import csv
from collections import Counter
from pathlib import Path

DATA = Path(__file__).parent / "data" / "windows_security_events.csv"
FAILURE_EVENT = "4625"
SUCCESS_EVENT = "4624"
THRESHOLD = 3

if not DATA.exists():
    raise SystemExit(f"Missing input file: {DATA}")

failed_by_ip = Counter()
failed_by_user = Counter()
success_count = 0
failed_count = 0
suspicious_sequences = []

with DATA.open(newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        event_id = row["event_id"].strip()
        ip = row["source_ip"].strip()
        user = row["username"].strip()
        if event_id == FAILURE_EVENT:
            failed_count += 1
            if ip and ip != "-":
                failed_by_ip[ip] += 1
            if user:
                failed_by_user[user] += 1
        elif event_id == SUCCESS_EVENT:
            success_count += 1

print("=== WINDOWS SECURITY EVENT INVESTIGATION ===")
print(f"Input: {DATA.name}")
print(f"Failed logons (4625): {failed_count}")
print(f"Successful logons (4624): {success_count}")
print("\nFailed logons by source IP:")
for ip, count in failed_by_ip.most_common():
    print(f"  {ip}: {count}")

print("\nFailed logons by account:")
for user, count in failed_by_user.most_common():
    print(f"  {user}: {count}")

print(f"\nPotential patterns (threshold: {THRESHOLD}+ failures per IP):")
alerts = [(ip, n) for ip, n in failed_by_ip.most_common() if n >= THRESHOLD]
if alerts:
    for ip, n in alerts:
        print(f"  [REVIEW] {ip} produced {n} failed logons")
else:
    print("  No source IP met the threshold.")

print("\nAnalyst note: threshold matches are leads, not proof of compromise.")
print("Correlate timestamps, account context, logon type, endpoint activity, and change records.")
