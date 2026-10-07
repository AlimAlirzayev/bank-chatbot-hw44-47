#!/usr/bin/env bash
# bot_log.csv-ni cədvəl (TSV) kimi buferə kopyalayır — Power BI veb: Create → Paste or manually enter data → Cmd+V
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -c "import csv,sys; w=csv.writer(sys.stdout, delimiter='\t', lineterminator='\n'); [w.writerow(r) for r in csv.reader(open('data/bot_log.csv', encoding='utf-8'))]" | pbcopy
echo "bot_log.csv buferdədir ($(($(wc -l < data/bot_log.csv) - 1)) sətir). Power BI-da Cmd+V edin."
