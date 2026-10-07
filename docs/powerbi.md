# Power BI: veb versiyada dashboard (Mac, təxminən 10 dəqiqə)

Hesab: app.powerbi.com → **Start free** → universitet və ya iş poçtu → poçta gələn kodu daxil edin.
Gmail kimi şəxsi poçt qəbul olunmur. Qeydiyyat mümkün olmasa ("Your organization doesn't allow"), eyni
göstəricilər demo səhifəsindəki dashboard-da da var.

## 1. Datanı yapışdır

Veb versiya CSV-ni birbaşa açmır, cədvəli yapışdırmaq lazımdır.

1. Repo qovluğunda terminalda: `scripts/copy_for_powerbi.sh`. Bu, `bot_log.csv`-ni cədvəl
   kimi buferə kopyalayır.
2. Power BI: **Create → Paste or manually enter data** → Cmd+V → **Use first row as headers** ✔ →
   cədvəlin adı `bot_log` → **Create**.
3. Rəqəmlər yanlış oxunsa (məsələn 0.0005 böyük rəqəm kimi görünürsə): sütuna sağ klik →
   **Change type → Using locale → English (United States)**.

## 2. Vizuallar (Edit rejimi)

| Vizual | Sahə | Aqreqasiya |
|---|---|---|
| Card — Söhbət sayı | `conversation_id` | Count |
| Card — Həll faizi | `resolved` | **Average** (format: %) |
| Card — Ümumi xərc | `cost_usd` | Sum |
| Card — Orta gecikmə | `latency_ms` | Average |
| Clustered column — mövzu üzrə həll faizi | X: `topic`, Y: `resolved` | Average |
| Donut — model üzrə xərc | Legend: `model`, Values: `cost_usd` | Sum |
| Slicer — kanal | `channel` | — |
| **Bonus:** Bar — təhlükəsizlik qatı | `gate_verdict`, Count of `conversation_id` | Count |

`resolved` 0 və 1-dən ibarətdir, ona görə onun **Average**-i birbaşa həll faizini verir.

## 3. Yoxlama — bu rəqəmlər çıxmalıdır

60 söhbət · 73.3% · $0.00538 · 640 ms. Ən zəif mövzu Kart (50%), ən baha model qwen (76%).
Slicer-də **WhatsApp** seçəndə bütün kartlar dəyişməlidir. Bu, filter context-dir (dərs #46, §7).

## 4. Təhvil

Dashboard-un ekran şəkli (Cmd+Shift+4) + `docs/answers.md`-dəki 3 cavab.
