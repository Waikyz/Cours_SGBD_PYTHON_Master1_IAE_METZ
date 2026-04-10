import csv
import random
from datetime import datetime, timedelta

random.seed(42)

# === ACCOUNTS ===
# Architecture:
# - 3 "hub" fraudulent accounts (receive large sums, then redistribute = structuring/smurfing)
# - 8 "mule" accounts (receive small fragmented transfers from hubs)
# - 5 "source" accounts (send large amounts to hubs)
# - 14 legitimate accounts (noise)

countries = ["DE", "FR", "IT", "ES", "NL", "PL", "RO", "NG", "CN", "RU"]
account_types = ["personal", "business", "personal", "personal", "business"]

accounts = []

for i in range(1, 31):
    if i <= 3:
        role = "HUB_FRAUD"
        country = random.choice(["NG", "RO", "CN"])
    elif i <= 11:
        role = "MULE"
        country = random.choice(["PL", "RO", "NG", "RU"])
    elif i <= 16:
        role = "SOURCE"
        country = random.choice(["DE", "FR", "IT"])
    else:
        role = "LEGIT"
        country = random.choice(["DE", "FR", "IT", "ES", "NL"])

    accounts.append({
        "account_id": f"N26-{i:04d}",
        "full_name": [
            "Aleksei Morozov", "Liu Wei", "Emeka Okafor",
            "Piotr Kowalski", "Marius Ionescu", "Yusuf Adeyemi",
            "Dmitri Volkov", "Ana Popescu", "Chidi Eze", "Bogdan Rus",
            "Sophie Martin", "Luca Rossi", "Carlos García",
            "Marie Dupont", "Hans Müller", "Elena Ionescu",
            "Jean Bernard", "Marco Ferrari", "Anna Schmidt", "Pedro Silva",
            "Laura Petit", "Thomas Weber", "Isabelle Moreau", "Felix Braun",
            "Camille Leroy", "David Bauer", "Nathalie Simon", "Stefan Koch",
            "Amélie Laurent", "Michael Hoffmann"
        ][i-1],
        "country": country,
        "account_type": random.choice(account_types),
        "opening_date": (datetime(2022, 1, 1) + timedelta(days=random.randint(0, 500))).strftime("%Y-%m-%d"),
        # Hub and mule accounts tend to have basic KYC (weak verification = N26 regulatory issue)
        "kyc_level": random.choice(["basic", "basic", "enhanced"]) if role in ["HUB_FRAUD", "MULE"] else "enhanced",
        "is_flagged": "TRUE" if role in ["HUB_FRAUD", "MULE"] else "FALSE",
        "role_label": role  # for teaching purposes
    })

# === TRANSACTIONS ===
transactions = []
tx_id = 1
base_date = datetime(2024, 1, 1)

hub_ids    = [f"N26-{i:04d}" for i in range(1, 4)]
mule_ids   = [f"N26-{i:04d}" for i in range(4, 12)]
source_ids = [f"N26-{i:04d}" for i in range(12, 17)]
legit_ids  = [f"N26-{i:04d}" for i in range(17, 31)]

def make_tx(sender, receiver, amount, date, tx_type, flagged):
    global tx_id
    t = {
        "transaction_id": f"TX-{tx_id:05d}",
        "sender_id": sender,
        "receiver_id": receiver,
        "amount_eur": round(amount, 2),
        "timestamp": (date + timedelta(
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )).strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_type": tx_type,
        "country_sender":   next(a["country"] for a in accounts if a["account_id"] == sender),
        "country_receiver": next(a["country"] for a in accounts if a["account_id"] == receiver),
        "is_suspicious": "TRUE" if flagged else "FALSE"
    }
    tx_id += 1
    return t

# --- Layer 1: Sources → Hubs (large wire transfers, dirty money arriving) ---
for hub in hub_ids:
    for source in source_ids:
        for month in range(1, 5):
            date = base_date + timedelta(days=(month - 1) * 30 + random.randint(0, 5))
            amount = random.uniform(8000, 25000)
            transactions.append(make_tx(source, hub, amount, date, "wire_transfer", True))

# --- Layer 2: Hubs → Mules (structuring/smurfing: many small transfers below €1000) ---
for hub in hub_ids:
    for month in range(1, 5):
        for mule in mule_ids:
            n_transfers = random.randint(2, 4)  # 2 to 4 transfers per mule per month
            for _ in range(n_transfers):
                date = base_date + timedelta(days=(month - 1) * 30 + random.randint(3, 25))
                amount = random.uniform(200, 950)  # Always just below €1000 detection threshold
                transactions.append(make_tx(hub, mule, amount, date, "instant_transfer", True))

# --- Layer 3: Legitimate transactions (noise to simulate real bank activity) ---
for _ in range(80):
    sender = random.choice(legit_ids + source_ids)
    receiver = random.choice(legit_ids)
    while receiver == sender:
        receiver = random.choice(legit_ids)
    date = base_date + timedelta(days=random.randint(0, 120))
    amount = random.uniform(10, 3000)
    transactions.append(make_tx(
        sender, receiver, amount, date,
        random.choice(["card_payment", "wire_transfer", "instant_transfer"]),
        False
    ))

# === AML FLAGS ===
# Automatically generated alerts based on two detection rules:
# - LARGE_INCOMING: any suspicious transaction above €5,000
# - STRUCTURING_PATTERN: suspicious small transfers (smurfing pattern)

flags = []
flag_id = 1

for tx in transactions:
    if tx["is_suspicious"] == "TRUE":
        if float(tx["amount_eur"]) > 5000:
            rule = "LARGE_INCOMING"
            severity = "HIGH"
        else:
            rule = "STRUCTURING_PATTERN"
            severity = "MEDIUM"
        flags.append({
            "flag_id": f"FLAG-{flag_id:04d}",
            "account_id": tx["receiver_id"],
            "transaction_id": tx["transaction_id"],
            "rule_triggered": rule,
            "severity": severity,
            "flag_date": tx["timestamp"][:10],
            "status": random.choice(["OPEN", "OPEN", "UNDER_REVIEW"])
        })
        flag_id += 1

# === WRITE CSVs ===
def write_csv(filename, data, fieldnames):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

write_csv('accounts.csv', accounts,
    ["account_id", "full_name", "country", "account_type", "opening_date", "kyc_level", "is_flagged", "role_label"])

write_csv('transactions.csv', transactions,
    ["transaction_id", "sender_id", "receiver_id", "amount_eur", "timestamp", "transaction_type",
     "country_sender", "country_receiver", "is_suspicious"])

write_csv('aml_flags.csv', flags,
    ["flag_id", "account_id", "transaction_id", "rule_triggered", "severity", "flag_date", "status"])

print(f"Accounts generated    : {len(accounts)}")
print(f"Transactions generated: {len(transactions)}")
print(f"AML Flags generated   : {len(flags)}")
print("CSV files saved: accounts.csv, transactions.csv, aml_flags.csv")
