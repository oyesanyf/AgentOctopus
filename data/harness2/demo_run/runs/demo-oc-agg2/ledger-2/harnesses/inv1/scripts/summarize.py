import csv
import os
import sys
from decimal import Decimal
from pathlib import Path

target = Path(sys.argv[1]).resolve()
if os.path.basename(sys.argv[1]) != 'ledger.csv':
    raise ValueError('Invalid filename')
lines = target.read_text(encoding='utf-8').splitlines()
amounts = [Decimal(row['amount']) for row in csv.DictReader(lines)]
total = sum((amount for amount in amounts if amount > 0), Decimal(0))
print(f'Total: {total:.2f}')
