# Kodun izahı

> Bu fayl `docs/tour.json`-dan avtomatik yaranır (`python -m demo.tour`). Eyni məzmun demo səhifəsinin **Kodun izahı** tabında da var.

```
bank-chatbot-hw44-47/
├── .github/
│   └── workflows/
│       └── ci.yml
├── demo/
│   └── app.py
├── scripts/
│   ├── harvest_preferences.py
│   └── simulate_traffic.py
├── tests/
│   ├── test_hardening.py
│   └── test_llm_service.py
├── llm_service.py
├── pipeline.py
└── security_gate.py
```

## `security_gate.py` · #44

Giriş yoxlaması: şəxsi məlumatın maskalanması, prompt injection aşkarlanması, rollara görə icazə, istifadəçi məlumatının izolyasiyası.

### PII maskalanması

**Dərs:** #44 · NVIDIA: input rails · [`security_gate.py` sətir 26–29](../security_gate.py#L26-L29)

```python
def mask_pii(text: str) -> str:
    text = CARD_RE.sub("[CARD]", text)
    text = PHONE_RE.sub("[PHONE]", text)
    return EMAIL_RE.sub("[EMAIL]", text)
```

```python
# Sıra vacibdir: əvvəl kart (15–19 rəqəm), sonra telefon — yoxsa kartın bir hissəsi telefona oxşayar.
# Hər təkrarın sayı məhduddur ({1,64}, {14,18}): məhdudiyyətsiz "+" uzun mətndə kvadratik vaxt aparır
# (ReDoS). Testdə 40 KB-lıq mesaj servisi 5 saniyə dayandırırdı.
_SEP = r"[ \t\n.\-/\u00a0]{0,3}"   # vergül YOX: "050…, 055…" siyahısı kart kimi birləşməsin
CARD_RE = re.compile(r"(?<!\d)(?:\d" + _SEP + r"){14,18}\d(?!\d)")
PHONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+|00)?994[ .\-]?\(?\d{2}\)?|\(?0\d{2}\)?)"
    r"[ .\-\n]?\d{3}[ .\-\n]?\d{2}[ .\-\n]?\d{2}(?!\d)"
)
EMAIL_RE = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}")
```

- **Nə edir:** Kart nömrəsi (15–19 rəqəm), telefon (+994, 050, 994…) və e-poçt [CARD], [PHONE], [EMAIL] ilə əvəz olunur. Model, cache və log yalnız maskalanmış mətni alır.
- **Niyə belə:** Əvvəl kart, sonra telefon yoxlanır, əks halda kart nömrəsinin bir hissəsi telefon kimi tanına bilər. Regex-lərdə təkrar sayı məhduddur ({1,64}). Məhdudiyyətsiz '+' uzun mətndə kvadratik vaxt aparır (ReDoS): testdə 40 KB-lıq mesaj servisi 5 saniyə dayandırırdı.
- **Qısa izah:** Şəxsi məlumat modelə göndərilməzdən əvvəl regex ilə maskalanır. Regex-lər uzun mətndə də xətti vaxtda işləyir.

### Prompt injection aşkarlanması

**Dərs:** #44 · NVIDIA: input rails · [`security_gate.py` sətir 64–66](../security_gate.py#L64-L66)

```python
def detect_injection(text: str) -> bool:
    t = _norm(text)
    return any(p.search(t) for p in _INJECTION_RE)
```

```python
INJECTION_PATTERNS = [
    # Qayda: yalnız ƏMR formasını tut. "Ödəniş göstərişini ləğv etmək istəyirəm" bank sorğusudur, hücum yox.
    # Ölçü dəsti: tests/eval_gate.json (scripts/eval_gates.py recall və yanlış-həyəcan faizini çap edir).
    # EN
    r"ignore (all |the |any |your )?(previous|prior|above|earlier) (instruction|rule|prompt)",
    r"forget (everything|all|what) (you were|you've been|previous|above|you know)",
    r"(reveal|show|print|repeat|tell)( me)? (your|the) (system prompt|hidden instructions|initial instructions)",
    r"(reveal|show|print|repeat) (me )?your (instructions|rules|prompt)\b(?! for)",
    r"what (is|are) your (system prompt|hidden (rules|instructions)|initial instructions)",
    r"(you are now|act as|pretend to be) .{0,30}(dan|developer mode|admin|unrestricted|jailbr)",
    # AZ (normallaşdırılmış: ı → i)
    r"(təlimat|qayda|göstəriş)\w* unut(un)?\b",
    r"(əvvəlki|bütün|sənin|sənə verilən|yuxaridaki) (təlimat|qayda)\w* (ləğv et|məhəl qoyma|nəzərə alma)(in)?\b",
    r"(təlimat|qayda)\w* (ləğv et|məhəl qoyma)(in)?\b(?! ?mək)",
    r"sistem (prompt|təlimat|mesaj)\w* .{0,15}(göstər|deyin|de\b|yaz|paylaş)",
    r"gizli (təlimat|prompt)\w* .{0,15}(göstər|deyin|de\b|yaz|paylaş)",
    r"(sən artiq|indi sən|bundan sonra sən|bundan sonra) .{0,40}(admin|məhdudiyyətsiz|qaydasiz)",
    # RU
    r"(игнорируй|забудь) (все )?(предыдущие )?(инструкции|правила)",
    r"(покажи|выведи|напиши) (свой |твой |свои |твои )(системный )?(промпт|prompt|инструкции)",
    r"системн\w* (промпт|prompt)",
]
```

- **Nə edir:** Mətn normallaşdırılır (kiçik hərf, ı→i, artıq boşluqlar silinir) və AZ, EN, RU şablonları ilə yoxlanır.
- **Niyə belə:** Yalnız əmr forması tutulur: 'Ödəniş göstərişini ləğv etmək istəyirəm' adi bank sorğusudur. Regex pulsuz və sürətlidir. Regex-in buraxdığı halları ikinci qat olaraq Llama Prompt Guard modeli yoxlayır.
- **Qısa izah:** İlk qat regex, ikinci qat ML klassifikatordur. Regex yeni ifadələrdə zəifdir, ona görə sonrakı yoxlamalar da var.

### Rollara görə icazə (default deny)

**Dərs:** #44 · [`security_gate.py` sətir 95–104](../security_gate.py#L95-L104)

```python
def execute_tool(role: str, tool_name: str, confirm=input) -> str:
    if tool_name not in TOOLS:                       # default deny: siyahıda yoxdursa — yoxdur
        return "Belə alət yoxdur"
    func, level = TOOLS[tool_name]
    if level not in ROLE_LEVELS.get(role, set()):    # naməlum rol = boş icazə
        return "İcazə yoxdur"
    if level == "destructive":                       # geri dönməyən əməliyyat — insan təsdiqi
        if confirm("Təsdiq edirsiniz? (b/x): ").strip().lower() != "b":
            return "Ləğv edildi"
    return func()
```

```python
ROLE_LEVELS = {
    "customer_bot": {"read"},
    "support_bot": {"read", "write"},
    "admin_bot": {"read", "write", "destructive"},
}
```

- **Nə edir:** Hər alətin səviyyəsi var (read, write, destructive), hər rolun icazələri var. Naməlum alət və ya rol rədd olunur. Destructive alət istifadəçi təsdiqi ('b') tələb edir.
- **Niyə belə:** confirm parametri susmaya görə input() funksiyasıdır. Testdə və demoda başqa funksiya ötürülür (dependency injection).
- **Qısa izah:** Siyahıda olmayan alət işləmir. Geri qaytarılmayan əməliyyat təsdiqsiz icra olunmur.

### İstifadəçi məlumatının izolyasiyası

**Dərs:** #44 · [`security_gate.py` sətir 111–115](../security_gate.py#L111-L115)

```python
def make_tools_for_user(session_user_id: str):
    """user_id parametr DEYİL — closure-un içində kilidlənib. Model onu dəyişə bilməz."""
    def get_my_balance() -> int:
        return BALANCES[session_user_id]
    return get_my_balance
```

- **Nə edir:** get_my_balance() parametr qəbul etmir. user_id closure daxilində sabitlənib.
- **Niyə belə:** Model alətə başqa user_id ötürə bilmir, ona görə başqa müştərinin balansını ala bilməz. Testdə regex-dən keçən hücumda da alət yalnız cari istifadəçinin balansını qaytardı.
- **Qısa izah:** İstifadəçi identifikatoru parametr kimi yox, closure ilə ötürülür, model onu dəyişə bilmir.

## `llm_service.py` · #45

LLM sorğusu: timeout, retry, fallback model, xərc qeydiyyatı, cache.

### LLM klienti: timeout=15, max_retries=0, max_tokens=200

**Dərs:** #45 · [`llm_service.py` sətir 79–85](../llm_service.py#L79-L85)

```python
def _client() -> openai.OpenAI:
    return openai.OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url=os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"),
        timeout=15,        # 15 s-dən çox gözləmirik
        max_retries=0,     # SDK-nın gizli retry-ı söndürülüb — retry-ı biz idarə edirik
    )
```

```python
def make_llm_call(system_prompt: str = SYSTEM_PROMPT):
    """llm_call(model, question) -> (mətn, input_tokens, output_tokens). Testdə saxtası ötürülür."""
    def llm_call(model: str, question: str):
        extra = {}
        if model.startswith("qwen/"):
            extra["reasoning_effort"] = "none"     # düşünmə tokenləri 200 limiti yeməsin
        elif "gpt-oss" in model:
            extra["reasoning_effort"] = "low"
        r = _client().chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": question}],
            max_tokens=200,
            **extra,
        )
        return (r.choices[0].message.content or "").strip(), r.usage.prompt_tokens, r.usage.completion_tokens
    return llm_call
```

- **Nə edir:** Groq API-yə OpenAI SDK ilə qoşulur. SDK-nın daxili retry-ı söndürülüb, retry məntiqi kodda idarə olunur. qwen üçün reasoning_effort='none' verilir ki, reasoning tokenləri 200 limitini doldurmasın.
- **Niyə belə:** Testdə gpt-oss-20b 200 tokendə kəsildi və mövcud olmayan bank nömrələri yazdı, ona görə istifadə olunmur.
- **Qısa izah:** Sorğu 15 saniyədən çox gözləmir, təkrar cəhdləri SDK yox, tətbiqin kodu idarə edir.

### Retry və exponential backoff

**Dərs:** #45 · NVIDIA: run and maintain · [`llm_service.py` sətir 117–132](../llm_service.py#L117-L132)

```python
def _try_model(model, question, llm_call, events):
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            text, i, o = llm_call(model, question)
            if text:
                return text, i, o
            events.append(f"{model}: boş cavab")
            return None
        except RETRYABLE as e:
            events.append(f"{model}: cəhd {attempt} — {type(e).__name__}")
            if attempt < MAX_ATTEMPTS:
                time.sleep(BACKOFF_BASE * 2 ** (attempt - 1))
        except Exception as e:                        # 401, 400 ... — təkrar etməyin mənası yoxdur
            events.append(f"{model}: {type(e).__name__} — təkrar edilmir")
            return None
    return None
```

```python
RETRYABLE = (openai.RateLimitError, openai.APITimeoutError)   # yalnız MÜVƏQQƏTİ xətalar
```

- **Nə edir:** Yalnız müvəqqəti xətalarda (429, timeout) 3 cəhd edilir: 1 s, sonra 2 s gözləmə ilə. 401 və 400 kimi xətalar təkrarlanmır.
- **Niyə belə:** Daimi xətanı təkrarlamaq vaxt və xərc artırır. Test time.sleep-i əvəz edir və gözləmələrin [1.0, 2.0] olduğunu yoxlayır.
- **Qısa izah:** Müvəqqəti xətada artan fasilə ilə üç cəhd edilir, daimi xətada dərhal fallback modelə keçilir.

### Cache, əsas model, fallback, xəta mesajı

**Dərs:** #45 · [`llm_service.py` sətir 135–159](../llm_service.py#L135-L159)

```python
def ask_detailed(question: str, llm_call=None, use_cache: bool = True, fail_primary: bool = False,
                 models=None) -> dict:
    llm_call = llm_call or groq_call
    key = " ".join(question.lower().split())
    if use_cache and key in _cache:
        return {"answer": _cache[key], "model": "cache", "cached": True, "failed": False,
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "events": ["cache: LLM çağırılmadı"]}

    events = []
    for model in models or (primary_model(), fallback_model()):
        call = _simulated_rate_limit if (fail_primary and model == primary_model()) else llm_call
        result = _try_model(model, question, call, events)
        if result:
            text, i, o = result[0], int(result[1] or 0), int(result[2] or 0)
            try:
                cost = log_cost(model, i, o)
            except OSError as e:                      # xərc faylı yazılmasa da cavab müştəriyə gedir
                cost = calc_cost(model, i, o)
                events.append(f"costs.csv yazılmadı: {type(e).__name__}")
            if use_cache:
                _cache[key] = text
            return {"answer": text, "model": model, "cached": False, "failed": False,
                    "input_tokens": i, "output_tokens": o, "cost_usd": cost, "events": events}
    return {"answer": POLITE_ERROR, "model": None, "cached": False, "failed": True,
            "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "events": events}
```

- **Nə edir:** Təkrar sual cache-dən qaytarılır, LLM çağırılmır. Sonra gpt-oss-120b, alınmasa qwen istifadə olunur. Hər ikisi əlçatmaz olduqda istifadəçi nəzakətli xəta mesajı alır, exception yaranmır.
- **Niyə belə:** Fallback model başqa model ailəsindəndir, eyni vaxtda əlçatmaz olma ehtimalı azdır. 60 söhbətdə cache 21 sorğunu LLM çağırmadan cavablandırdı.
- **Qısa izah:** LLM xətası istifadəçiyə exception kimi çatmır, həmişə cavab qaytarılır.

### Xərcin hesablanması və costs.csv

**Dərs:** #45 · #46 · [`llm_service.py` sətir 57–61](../llm_service.py#L57-L61)

```python
def calc_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    p = PRICES.get(model)
    if not p:
        return 0.0
    return round((input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000, 8)
```

```python
PRICES = {
    "qwen/qwen3.8-27b": {"input": 0.80, "output": 4.00},
    "openai/gpt-oss-120b": {"input": 0.15, "output": 0.60},
    "openai/gpt-oss-20b": {"input": 0.075, "output": 0.30},
}
```

- **Nə edir:** Groq-un rəsmi qiymətləri (USD / 1M token) PRICES lüğətindədir. Hər uğurlu sorğu costs.csv-yə bir sətir yazır.
- **Niyə belə:** qwen çıxış tokeni $4.00, gpt-oss-120b $0.60-dır. Dashboard-da qwen 9 söhbətdə ümumi xərcin 76%-ni təşkil edir.
- **Qısa izah:** Hər sorğunun xərci hesablanır və qeyd olunur. Model seçimi bu məlumata əsaslanır.

## `pipeline.py` · #44–#47

Sorğunun emalı beş mərhələdə: giriş yoxlaması, LLM sorğusu, çıxış yoxlaması, loglama, DPO datası.

### handle(): beş emal mərhələsi

**Dərs:** #44–#47 · NVIDIA: observability · [`pipeline.py` sətir 193–293](../pipeline.py#L193-L293)

```python
def handle(message: str, role: str = "customer_bot", user_id: str = "user_1", channel: str = "web",
           llm_call=None, guard_call=None, fail_primary: bool = False, red_team: bool = False,
           confirm: bool = False, timestamp: str = None) -> dict:
    trace_id = uuid.uuid4().hex[:12]
    trace, clock, t0 = [], _Clock(), time.perf_counter()
    guard_call = guard_call or default_guard_call
    topic = classify_topic(message)

    # ① GATE — ölçü yoxla, PII maskala, injection yoxla (regex + Prompt Guard)
    if not message.strip() or len(message) > MAX_MESSAGE_CHARS:
        masked, regex_hit, score, attack = "", False, None, True
        detail = "boş mesaj" if not message.strip() else f"mesaj çox uzundur ({len(message)} > {MAX_MESSAGE_CHARS})"
    else:
        masked = mask_pii(message)
        pii_n = (len(re.findall(r"\[(EMAIL|PHONE|CARD)\]", masked))
                 - len(re.findall(r"\[(EMAIL|PHONE|CARD)\]", message)))
        regex_hit = detect_injection(message)
        detail = f"PII maskalandı: {pii_n}; regex: {'hücum' if regex_hit else 'təmiz'}"
        score = None
        if not regex_hit:
            try:
                raw_score = guard_call(masked)
                score = None if raw_score is None else float(raw_score)
                if score is not None and not (0.0 <= score <= 1.0):          # NaN / inf / mənasız bal = xəta
                    score = None
                    raise ValueError(f"guard score {raw_score!r}")
                detail += f"; Prompt Guard: {score:.3f}" if score is not None else "; Prompt Guard: söndürülüb"
            except Exception as e:
                detail += f"; Prompt Guard XƏTA ({type(e).__name__}) — yalnız regex qatı işlədi"
        attack = regex_hit or (score is not None and score >= GUARD_THRESHOLD)
    trace.append({"name": "gate", "status": "blocked" if attack else "ok", "ms": clock.lap(), "detail": detail})

    model, tin, tout, cost, failed, verdict = "", 0, 0, 0.0, False, "ok"
    if attack:
        answer, verdict = (BLOCKED_INPUT_ANSWER if masked else "Zəhmət olmasa sualınızı qısa yazın."), "blocked_input"
        trace.append({"name": "llm", "status": "skipped", "ms": 0, "detail": "hücum modelə çatmadı"})
    elif (tool := _tool_intent(masked)) and not red_team:
        # alət yolu — icazəni execute_tool yoxlayır, balansı closure verir (izolyasiya)
        result = execute_tool(role, tool, confirm=lambda _p: "b" if confirm else "x")
        if tool == "get_balance" and result.startswith("Balans"):
# … (tam kod yuxarıdakı linkdədir)
```

- **Nə edir:** Mesaj ardıcıl olaraq gate, llm, output_rail, log və harvest mərhələlərindən keçir. Hər mərhələ trace-ə {name, status, ms, detail} yazır, demo səhifəsi bu məlumatı göstərir.
- **Niyə belə:** Trace hər mərhələnin müddətini və nəticəsini göstərir (observability). Log yazıla bilməsə də istifadəçi cavab alır.
- **Qısa izah:** Bir funksiya beş mərhələni icra edir, hər mərhələnin nəticəsi və müddəti trace-də qeyd olunur.

### Çıxış yoxlaması: məxfi məlumat tələbi

**Dərs:** #44 · #47 · NVIDIA: output rails · [`pipeline.py` sətir 120–127](../pipeline.py#L120-L127)

```python
def violates_secret_rule(text: str) -> bool:
    """Cavab müştəridən sirr (PIN/CVV/SMS kod/kartın tam nömrəsi) İSTƏYİRMİ?"""
    for raw in _sentences(text):
        sentence = _drop_bare_conditionals(_PARTIAL.sub("", _norm(raw)))
        for clause in _CLAUSE_BREAK.split(sentence):       # "…başqasına verməyin, amma mənə göndərin"
            if clause and _SECRET.search(clause) and _is_request(clause) and not _NEGATED_REQUEST.search(clause):
                return True
    return False
```

```python
def _sentences(text: str):
    """Cümlələr. Siyahı yalnız BAŞLIĞI sorğu olanda ona birləşir ("göndərin:\n1. Kart nömrəsi\n2. CVV").
    "Kart itibsə:\n1. … 3. PIN-i təyin edin\n4. Bizə yazın" — ayrı addımlardır, birləşmir."""
    out, header = [], None
    for line in text.splitlines():
        if not line.strip():
            continue                                       # boş sətir başlıqla siyahını qırmır
        if _LIST_ITEM.match(line):
            item = _LIST_ITEM.sub("", line)
            if header is not None:
                out[-1] += ", " + item
            else:
                out.append(item)
            continue
        header = None
        for part in re.split(r"(?<=[.!?])\s+", line.strip()):
            out.append(part)
        if line.rstrip().endswith(":") and _is_request(_norm(line)):
            header = True
    return out
```

- **Nə edir:** Cümlədə məxfi məlumat sözü (PIN, CVV, SMS kod, kartın tam nömrəsi) və sorğu feli (göndərin, yazın, nədir?) varsa və fel inkar formada deyilsə, cavab pozuntu sayılır.
- **Niyə belə:** Xəbərdarlıq ('PIN-i heç kimə deməyin') pozuntu deyil. Siyahı yalnız başlıq sorğu olduqda birləşdirilir. Yoxlama leksikdir: held-out dəstdə təxminən 75–80% tutur.
- **Qısa izah:** Modelin cavabının istifadəçiyə göndərilib-göndərilməməsinə qayda əsasında kod qərar verir.

### DPO datasının toplanması

**Dərs:** #47 · red teaming · [`pipeline.py` sətir 274–290](../pipeline.py#L274-L290)

```python
    # ⑤ HARVEST — tutulan pis cavab = DPO cütlüyü (rejected), təhlükəsiz cavab = chosen
    if rejected:
        ratio = len(SAFE_ANSWER) / max(len(rejected), 1)
        if RATIO_MIN <= ratio <= RATIO_MAX:
            try:   # prompt = MASKALANMIŞ mətn: təlim datasına PII düşmür
                _append_jsonl(Path(os.getenv("HARVEST_JSONL", "data/harvest_live.jsonl")),
                              {"prompt": masked, "chosen": SAFE_ANSWER, "rejected": rejected})
                trace.append({"name": "harvest", "status": "pair", "ms": clock.lap(),
                              "detail": f"yeni DPO cütlüyü (uzunluq nisbəti {ratio:.2f})"})
            except OSError as e:
                trace.append({"name": "harvest", "status": "failed", "ms": clock.lap(),
                              "detail": f"cütlük yazılmadı: {e}"})
        else:
            trace.append({"name": "harvest", "status": "skipped", "ms": clock.lap(),
                          "detail": f"uzunluq balansı pozulur ({ratio:.2f}) — saxlanmadı"})
    else:
        trace.append({"name": "harvest", "status": "idle", "ms": clock.lap(), "detail": "toplanacaq pozuntu yoxdur"})
```

- **Nə edir:** Çıxış yoxlaması pozuntu tapanda: rejected = modelin cavabı, chosen = təhlükəsiz cavab, prompt = maskalanmış mesaj.
- **Niyə belə:** Cütlük yalnız uzunluq nisbəti 0.6–1.6 aralığında olduqda saxlanılır. Əks halda DPO cavabın uzunluğunu keyfiyyət əlaməti kimi öyrənə bilər.
- **Qısa izah:** Çıxış yoxlamasında tutulan cavablar DPO üçün preference cütlüyünə çevrilir.

### Loglama: bot_log.csv

**Dərs:** #46 · NVIDIA: audit trail · [`pipeline.py` sətir 259–272](../pipeline.py#L259-L272)

```python
    # ④ LOG — Power BI üçün bir söhbət = bir sətir; gate_verdict = 6-cı qat (təhlükəsizlik)
    resolved = int(verdict in ("ok", "tool") and not failed)
    latency = int((time.perf_counter() - t0) * 1000)
    log_row = {"conversation_id": trace_id,
                 "timestamp": timestamp or dt.datetime.now().isoformat(timespec="seconds"),
                 "channel": CHANNELS.get(channel.lower(), "Web"), "topic": topic, "model": model,
                 "input_tokens": tin, "output_tokens": tout, "cost_usd": f"{cost:.8f}",
                 "latency_ms": latency, "resolved": resolved, "gate_verdict": verdict}
    try:                                  # log yazılmasa da müştəri cavabını alır
        _append_log(log_row)
        trace.append({"name": "log", "status": "ok", "ms": clock.lap(),
                      "detail": f"{topic} · {CHANNELS.get(channel.lower(), 'Web')} · resolved={resolved}"})
    except OSError as e:
        trace.append({"name": "log", "status": "failed", "ms": clock.lap(), "detail": f"log yazılmadı: {e}"})
```

- **Nə edir:** Hər söhbət bir sətirdir: kanal, mövzu, model, token, xərc, gecikmə, resolved, gate_verdict.
- **Niyə belə:** gate_verdict dərsdəki altı qatlı metrika çərçivəsində çatışmayan təhlükəsizlik qatıdır. Power BI dashboard bu fayldan qurulur.
- **Qısa izah:** Loga təhlükəsizlik sahəsi əlavə olunub: hansı kanaldan neçə hücum gəldiyi görünür.

## `demo/app.py` · demo

FastAPI tətbiqi: demo səhifəsi, /api/ask, /api/stats və kodun izahı üçün endpoint-lər.

[Fayla bax](../demo/app.py)

## `scripts/harvest_preferences.py` · #47

Red teaming ilə 15 DPO cütlüyünün toplanması və kodla yoxlanması.

### Red teaming və avtomatik yoxlama

**Dərs:** #47 · [`scripts/harvest_preferences.py` sətir 87–112](../scripts/harvest_preferences.py#L87-L112)

```python
def main(out="data/preferences.jsonl"):
    naive, guarded = paced(llm_service.make_llm_call(NAIVE_PROMPT)), paced(llm_service.make_llm_call())
    red, good = llm_service.red_team_model(), llm_service.primary_model()
    pairs, reasons = [], Counter()
    for prompt in SITUATIONS:
        if len(pairs) >= TARGET:
            break
        rejected = next((t for t in (naive(red, prompt)[0] for _ in range(2)) if violates_secret_rule(t)), None)
        if rejected is None:
            reasons["təhlükəsiz olmayan prompt 2 cəhddə pozuntu yaratmadı"] += 1
            continue
        chosen = guarded(good, prompt)[0]
        if violates_secret_rule(chosen):
            reasons["əsas prompt ilə cavab da məxfi məlumat istədi"] += 1
            continue
        ratio = len(chosen) / max(len(rejected), 1)
        if not RATIO_MIN <= ratio <= RATIO_MAX:
            reasons[f"uzunluq balansı pozulur"] += 1
            continue
        pairs.append({"prompt": prompt, "chosen": chosen, "rejected": rejected})
        print(f"[{len(pairs):2}] +  {prompt}  (nisbət {ratio:.2f})")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in pairs), encoding="utf-8")
    print(f"\nSaxlanıldı: {len(pairs)} cütlük → {out}")
    for r, n in reasons.items():
        print(f"Atıldı: {n} — {r}")
```

- **Nə edir:** rejected cavab qwen modeli və qəsdən təhlükəsiz olmayan system prompt ilə, chosen cavab gpt-oss-120b və əsas system prompt ilə alınır. Kod yoxlayır: rejected məxfi məlumat istəyir, chosen istəmir, uzunluq nisbəti normadadır.
- **Niyə belə:** Testdə gpt-oss-120b təhlükəsiz olmayan promptu 5 cəhddən 5-də rədd etdi, qwen isə təxminən hər 3 cəhddən 1-də CVV istədi. Dataset qwen kimi modellərin bu davranışı öyrənməsi üçündür.
- **Qısa izah:** Etiketləri model yox, kod təyin edir. 15 cütlüyün hamısı əl ilə də yoxlanılıb.

## `scripts/simulate_traffic.py` · #46

60 söhbəti tam emal axınından keçirib bot_log.csv faylını yaradır.

[Fayla bax](../scripts/simulate_traffic.py)

## `tests/test_llm_service.py` · #45

LLM xidmətinin testləri saxta LLM funksiyası ilə: cache, xərc, retry, fallback.

### Test: saxta LLM ilə retry

**Dərs:** #45 · [`tests/test_llm_service.py` sətir 43–56](../tests/test_llm_service.py#L43-L56)

```python
def test_retry_three_times_then_fallback(monkeypatch):
    sleeps, calls = [], []
    monkeypatch.setattr(llm_service.time, "sleep", sleeps.append)

    def llm_call(model, question):
        calls.append(model)
        if model == llm_service.primary_model():
            rate_limited(model, question)
        return "ehtiyat cavab", 10, 5

    r = ask_detailed("sual", llm_call=llm_call)
    assert calls == [llm_service.primary_model()] * 3 + [llm_service.fallback_model()]
    assert sleeps == [1.0, 2.0]                      # exponential backoff
    assert r["model"] == llm_service.fallback_model() and r["answer"] == "ehtiyat cavab"
```

- **Nə edir:** Əsas model həmişə 429 qaytarır. Test 3 cəhdi, [1.0, 2.0] gözləmələrini və fallback modelə keçidi yoxlayır.
- **Niyə belə:** API açarı və internet tələb olunmur, ona görə test GitHub CI-da da işləyir.
- **Qısa izah:** Testlər saxta LLM ilə işləyir, CI API açarı olmadan keçir.

## `tests/test_hardening.py` · #44–#47

Müstəqil testdə tapılan xətalar üçün reqressiya testləri.

### Test: sənədləşdirilmiş məhdudiyyətlər

**Dərs:** test · [`tests/test_hardening.py` sətir 201–207](../tests/test_hardening.py#L201-L207)

```python
def test_documented_limits_are_true():
    """README-dəki 'bilinən buraxılış / yanlış həyəcan' siyahıları ölçü ilə üst-üstə düşməlidir.
    Kod birini düzəltsə, bu test qırmızı olur və sənəd yenilənməlidir."""
    from pathlib import Path
    d = json.loads((Path(__file__).parent / "eval_gate.json").read_text(encoding="utf-8"))
    assert [t for t in d["known_misses_documented"] if violates_secret_rule(t)] == []
    assert [t for t in d["known_false_alarms_documented"] if not violates_secret_rule(t)] == []
```

- **Nə edir:** README-də göstərilən buraxılan cümlələrin həqiqətən buraxıldığını, yanlış həyəcan cümlələrinin isə həqiqətən tutulduğunu yoxlayır.
- **Niyə belə:** Kod dəyişib bu hallardan birini düzəltsə, test uğursuz olur və sənəd yenilənməlidir.
- **Qısa izah:** Məhdudiyyətlər də testlə yoxlanılır ki, sənəd kodla uyğun qalsın.

## `.github/workflows/ci.yml` · #45

Hər push-da GitHub Actions pytest işlədir.

### CI: hər push-da pytest

**Dərs:** #45 · [`.github/workflows/ci.yml` sətir 1–14](../.github/workflows/ci.yml#L1-L14)

```yaml
name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements-ci.txt
      - run: pytest -q
```

- **Nə edir:** GitHub Actions Python 3.12 qurur, requirements-ci.txt paketlərini yükləyir və pytest işlədir.
- **Niyə belə:** API açarı repoda yoxdur (.env .gitignore-dadır), testlər saxta LLM ilə işləyir.
- **Qısa izah:** Hər push-da testlər avtomatik işləyir.

