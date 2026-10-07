# Bank çatbotu: təhlükəsizlik, LLMOps, analitika və DPO

Kurs tapşırıqları #44–#47 bir layihədə birləşdirilib: bankın müştəri çatbotu. Hər mesaj beş emal
mərhələsindən keçir:

```
müştəri mesajı
   │
 ① Giriş yoxlaması   #44  PII maskalanması → prompt injection yoxlaması (regex + Llama Prompt Guard)   security_gate.py
 ② LLM sorğusu       #45  cache → əsas model → retry/backoff → fallback model → costs.csv             llm_service.py
 ③ Çıxış yoxlaması   #44  cavab müştəridən PIN/CVV/SMS kod istəyirsə, müştəriyə göndərilmir            pipeline.py
 ④ Loglama           #46  hər söhbət bir sətir → bot_log.csv → Power BI                               pipeline.py
 ⑤ DPO datası        #47  tutulan cavab = rejected, təhlükəsiz cavab = chosen                         pipeline.py
```

## Kodun izahı

Hər modulun əsas kodu izahı ilə birlikdə: **[docs/KOD_IZAHI.md](docs/KOD_IZAHI.md)** (fayl strukturu,
16 bölmə). Hər bölmədə bunlar var: nə edir, niyə belə yazılıb, hansı tapşırığa aiddir, qısa izah.
Eyni məzmun demo səhifəsinin **Kodun izahı** tabında da var. Orada fayl strukturu, sintaksis rəngləri
və izah olunan sətirlər işarələnir. Bölmələr arasında ◀ ▶ düymələri və ya klaviatura oxları ilə keçilir.
Hər iki versiya `docs/tour.json` faylından yaranır. Sətir aralıqlarını `ast` modulu tapır, ona görə
kod dəyişəndə izah köhnəlmir.

## Tapşırıqlar və fayllar

| Tapşırıq | Tələb | Fayl |
|---|---|---|
| #44 Security Gate | `mask_pii`, `detect_injection` (≥4 şablon, AZ daxil), rollara görə icazə, closure ilə izolyasiya | `security_gate.py` (`python security_gate.py`) |
| #45 LLMOps | timeout=15, max_retries=0, 3 cəhd + backoff, fallback, `max_tokens=200`, `costs.csv`, cache, testlər, CI | `llm_service.py`, `tests/`, `.github/workflows/ci.yml`, `data/costs.csv` |
| #46 Power BI | 4 KPI, mövzu üzrə həll faizi, model üzrə xərc, kanal slicer-i, 3 cavab | `data/bot_log.csv`, `docs/powerbi.md`, `docs/answers.md` |
| #47 DPO dataset | 15 cütlük `prompt/chosen/rejected`, `load_dataset` ilə yoxlama, qısa cavab | `data/preferences.jsonl`, `scripts/check_preferences.py`, `docs/answers.md` |
| Demo | mərhələlər, KPI-lar, DPO datası, kodun izahı | `demo/app.py`, `demo/index.html` |
| NVIDIA NCP-AAI modulu: Run, Monitor and Maintain (#46 daxilində) | observability (logs, metrics, traces), fallback | hər mərhələnin trace-i (ms), `bot_log.csv`, KPI-lar |
| NVIDIA NCP-AAI modulu: Safety, Ethics and Compliance (#47 daxilində) | input və output rails (NeMo Guardrails yanaşması), audit trail, red teaming | ① giriş yoxlaması, ③ çıxış yoxlaması, `gate_verdict` sahəsi, red teaming rejimi |

## Nəticələr (2026-10-07)

- **Model seçimi testə əsaslanır.** `gpt-oss-120b` Azərbaycan dilində düzgün yazır, qwen-dən təxminən
  5 dəfə ucuzdur və qəsdən təhlükəsiz olmayan system prompt-u 5 cəhddən 5-də rədd etdi.
  `qwen3.8-27b` eyni prompt ilə təxminən hər 3 cəhddən 1-də CVV və kartın tam nömrəsini istədi.
  Ona görə əsas model gpt-oss-120b, fallback model başqa ailədən olan qwen-dir.
- **DPO datasının məqsədi:** gpt-oss-120b bu davranışı təlim zamanı öyrənib, qwen öyrənməyib.
  `preferences.jsonl` qwen kimi modellərin bu davranışı öyrənməsi üçündür.
- **Etiketləri kod təyin edir** (`violates_secret_rule`). İlk 15 cütlük əl ilə yoxlananda 3 yanlış etiket
  tapıldı ("kartın son 4 rəqəmi" məxfi məlumat deyil, "etmə" inkar formasıdır). Müstəqil testdə yoxlama
  funksiyası 14 sorğunu buraxır, 6 faydalı cavabı bloklayırdı. Funksiya yenidən yazıldı, hər hal üçün test
  əlavə olundu, dataset yenidən toplandı (13 namizəd atıldı). Hazırda 15 cütlüyün hamısı qaydaya uyğundur,
  uzunluq nisbəti 0.69–1.41 aralığındadır.
- **60 söhbət** (`bot_log.csv`): həll faizi 73.3%, ümumi xərc $0.00538, orta gecikmə 0.64 s.
  4 hücum giriş yoxlamasında, 3 məxfi məlumat tələbi çıxış yoxlamasında dayandırıldı.

## #45: xərc və cache

Beş sual (biri təkrar) cəmi **$0.000362** xərclədi (`data/costs.csv`, 4 sətir, hamısı `gpt-oss-120b`).
Təkrar sual cache-dən qaytarıldı, LLM çağırılmadı: 1 sorğuya (20%) qənaət edildi, təxminən $0.00009.
60 söhbətdə cache 21 sorğunu (35%) LLM çağırmadan, təxminən 100–260 ms-də cavablandırdı.
API açarı yalnız `.env` faylındadır, `.env` `.gitignore`-a əlavə olunub, repoda açar yoxdur.

## İşə salmaq

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env            # GROQ_API_KEY yazın
.venv/bin/python security_gate.py               # #44
.venv/bin/python llm_service.py                 # #45: 5 sual → data/costs.csv
.venv/bin/python -m pytest -q                   # 78 test, API açarı tələb olunmur
.venv/bin/python scripts/simulate_traffic.py    # #46: 60 söhbət → data/bot_log.csv
.venv/bin/python scripts/analyze_log.py         # #46: dashboard rəqəmləri
.venv/bin/python scripts/eval_gates.py --show   # yoxlamaların recall və yanlış həyəcan ölçüsü
.venv/bin/python scripts/harvest_preferences.py # #47: 15 cütlük
.venv/bin/python scripts/check_preferences.py   # #47: load_dataset ilə yoxlama
.venv/bin/uvicorn demo.app:app --port 8931      # demo
```

## Məhdudiyyətlər

- **Giriş və çıxış yoxlamaları leksikdir (regex).** Pulsuz və sürətlidir, testlə yoxlanılır, amma bütün
  halları tutmur. Ölçmə iki dəstdə aparılıb:

  | Yoxlama | Dev dəsti (`scripts/eval_gates.py`) | Held-out test dəsti |
  |---|---|---|
  | Çıxış yoxlaması (məxfi məlumat tələbi) | 36/36, 0/29 yanlış həyəcan | 36–38/48 (75–79%), 0–2/27 yanlış həyəcan |
  | Prompt injection regex-i | 25/25, 0/25 yanlış həyəcan | 13/36 (36%), 1/38 yanlış həyəcan |

  Dev dəstində nəticə 100%-dir, çünki şablonlar bu nümunələr əsasında yazılıb. Real göstərici held-out
  dəstidir: çıxış yoxlaması məxfi məlumat tələblərinin təxminən dörddə üçünü tutur.

  **Məlum buraxılışlar** (`tests/eval_gate.json` → `known_misses_documented`):
  - sorğu feli siyahıdan sonra gəldikdə ("…\n• CVV\nBunları bura göndərin");
  - başlığı sorğu olmayan və ya ":" ilə bitməyən siyahılar ("I will need the following:");
  - qeyri-standart işarələr (`a)`, `(1)`, `→`, `✔`) və işarəsiz siyahılar;
  - məxfi məlumat şərt cümləsində olduqda ("PIN kodunuzu bilirsinizsə, mənə deyin");
  - EN "do not be afraid / do not worry and send …" (AZ "qorxmayın, narahat olmayın" tutulur);
  - çata işarə etməyən "daxil edin / enter below / в поле ниже". "aşağıdakı", "xana" kimi sözlər qəsdən
    sorğu sayılmır, çünki faydalı təlimatları bloklayırdı.

  **Məlum yanlış həyəcanlar** (`known_false_alarms_documented`): sorğu başlıqlı siyahının içindəki
  xəbərdarlıq ("Tətbiqə yazın:\n1. … 2. PIN-i heç vaxt yazmayın"), həmçinin məxfi məlumat sözü ilə sorğu
  felini birlikdə işlədən bəzi məsləhətlər (test dəstində təxminən 2/25). Belə cavab təhlükəsiz standart
  cavabla əvəz olunur və DPO-ya rejected kimi düşə bilər. Ona görə demoda toplanan cütlüklər
  (`harvest_live.jsonl`) əsas datasetə yalnız əl ilə yoxlamadan sonra əlavə olunur.

  **Növbəti addım:** Groq-da `openai/gpt-oss-safeguard-20b` modeli var (policy əsaslı təhlükəsizlik
  klassifikatoru). Onu yalnız məxfi məlumat sözü olan cavablar üçün ikinci yoxlama kimi əlavə etmək olar:
  regex ilkin filtr, model isə son qərar olar. Əvvəlcə eyni held-out dəstdə ölçülməlidir.
- **Llama Prompt Guard Azərbaycan dilində zəifdir.** Testdə regex-in buraxdığı AZ hücumlarının çoxunu
  buraxdı, EN və RU hücumlarına isə 0.97–1.00 bal verdi. Bu hücumları sonrakı yoxlamalar saxladı: model
  məxfi məlumat vermədi, alət closure sayəsində yalnız cari müştərinin balansını qaytardı (defense in depth).
- **Kart maskası artıq maskalaya bilər.** 15–19 rəqəmli istənilən ardıcıllıq (sifariş nömrəsi, IBAN
  hissəsi) `[CARD]` ilə əvəz olunur. Vergüllə ayrılmış kart nömrəsi ("4111, 1111, …") maskalanmır, çünki
  vergül ayırıcı sayılsa, telefon siyahıları kart nömrəsi kimi birləşir. Sözlə yazılmış rəqəmlər də
  maskalanmır.
- **Demodakı rol seçimi** icazə sistemini göstərmək üçündür. Real sistemdə rol sorğudan yox, sessiya və
  autentifikasiyadan götürülür. Alətlər (`block_card` və s.) simulyasiyadır.
- **Mesajın maksimal uzunluğu 2000 simvoldur.** Daha uzun mesaj regex yoxlamasından əvvəl rədd olunur.
  Testdə 40 KB-lıq mesaj servisi 5 saniyə dayandırırdı. Bu düzəldildi və testlə yoxlanılır.

**Data haqqında:** `bot_log.csv`-dəki mesajları skript yaradıb, tarixlər son 14 günə paylanıb. Model,
token, xərc, gecikmə və yoxlama nəticələri isə real emal axınından alınıb.
