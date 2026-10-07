# Tapşırıqların yazılı cavabları

## #46: Power BI (data: `data/bot_log.csv`, 60 söhbət)

Dashboard göstəriciləri (`scripts/analyze_log.py`): **60 söhbət, həll faizi 73.3%, ümumi xərc $0.00538,
orta gecikmə 0.64 s.**

**1. Bot hansı mövzuda ən zəifdir? Bunun texniki səbəbi nə ola bilər?**
Ən zəif mövzu **Kart (50%)**-dır. 5 həll olunmayan söhbətdən 3-ü "Kartımı blokla" sorğusudur. Müştəri
botunun (`customer_bot`) yalnız `read` icazəsi var, `block_card` aləti isə `destructive` səviyyədədir,
ona görə bot "İcazə yoxdur" cavabı verir. Bu, model xətası deyil, icazə qaydasının nəticəsidir. Qalan
2 halın birində çıxış yoxlaması məxfi məlumat tələbini dayandırıb, digərində hər iki model əlçatmaz olub.
Həll yolu: kartın bloklanması üçün mobil tətbiqdəki "Kartı blokla" bölməsinə birbaşa keçid vermək və ya
sorğunu istifadəçi təsdiqi ilə `support_bot`-a ötürmək.

**2. Ən baha model hansıdır? Router məntiqini necə dəyişərdiniz?**
Ən baha model **qwen3.8-27b**-dir: 9 söhbətdə ümumi xərcin **76%-i** ($0.00409). Bir söhbətin orta xərci
qwen-də $0.000455, gpt-oss-120b-də $0.000085-dir, yəni 5.4 dəfə çoxdur. Çıxış tokenlərinin sayı təxminən
eynidir (~90), fərq qiymətdədir: 1M çıxış tokeni qwen-də $4.00, gpt-oss-120b-də $0.60. qwen fallback
modeldir və yalnız əsas model əlçatmaz olduqda istifadə olunur. Router dəyişikliyi: sadə suallar (filial
saatları, limitlər) üçün fallback kimi daha ucuz model seçmək, qwen-i yalnız mürəkkəb mövzular üçün
saxlamaq və cache-i genişləndirmək. Cache hazırda sorğuların 35%-ni LLM çağırmadan cavablandırır.

**3. Altı qatlı metrika çərçivəsindən hansı qatlar yoxdur? Hansı yeni sahəni təklif edirsiniz?**
Altı qat: keyfiyyət, xərc, sürət, istifadə, biznes dəyəri, təhlükəsizlik. Dərsdəki `bot_demo.csv`
faylında (bizim `bot_log.csv` də eyni sütunlarla başlayır) keyfiyyət (`resolved`), xərc (`cost_usd`),
sürət (`latency_ms`) və istifadə (`channel`, `topic`) var. **Biznes dəyəri** və **təhlükəsizlik**
qatları yoxdur. Loga **`gate_verdict`** sahəsini əlavə etdim (`ok`, `tool`, `blocked_input`,
`blocked_output`). Bu sahə bu suala cavab verir: *"Hansı kanaldan neçə hücum gəlir və bot neçə məxfi
məlumat sızmasının qarşısını aldı?"* Datada WhatsApp və Web kanallarından 4 prompt injection hücumu
gəlib, 3 cavab isə müştəridən məxfi məlumat istədiyi üçün dayandırılıb.

## #47: DPO (`data/preferences.jsonl`, 15 cütlük)

**Davranış:** bot müştəridən heç vaxt PIN, CVV, SMS kodu və ya kartın tam nömrəsini istəmir.

**Niyə bu problemi prompt engineering ilə deyil, DPO ilə həll etmək daha məqsədəuyğundur?**
System prompt-dakı təlimat modelin davranışına zəmanət vermir. Testdə qwen modelinə "kart məlumatlarını
soruş" deyən prompt verildikdə, model təxminən hər 3 cavabdan 1-də CVV istədi. gpt-oss-120b isə eyni
prompt-u 5 cəhddən 5-də rədd etdi, çünki bu davranışı təlim zamanı öyrənib. DPO davranışı modelin
çəkilərinə öyrədir, ona görə sonradan səhv yazılmış system prompt da bu qaydanı pozmur.

**`chosen` və `rejected` arasında uzunluq balansını necə qorudunuz?**
Hər cütlükdə `len(chosen) / len(rejected)` nisbəti 0.6 ilə 1.6 arasında olmalıdır. Bu aralıqdan kənar
5 cütlük avtomatik atıldı. Nəticə: minimum 0.69, maksimum 1.41, orta 1.12. Balans olmasa, model cavabın
uzunluğunu keyfiyyət əlaməti kimi öyrənə bilər.

**Etiketlərin keyfiyyəti:** `rejected` cavab məxfi məlumat istəyir, `chosen` istəmir. Bunu model yox,
`violates_secret_rule()` funksiyası yoxlayır. İlk versiya əl ilə yoxlananda 3 yanlış etiket tapıldı.
Müstəqil testdə funksiya 14 sorğunu buraxır, 6 faydalı cavabı isə bloklayırdı. Funksiya yenidən yazıldı,
testlər əlavə olundu və dataset yenidən toplandı. Məlum risk: chosen (gpt-oss-120b) və rejected (qwen)
fərqli modellərdəndir (off-policy), ona görə DPO üslub fərqini də öyrənə bilər.

## #45: xərc və cache

5 sual (biri təkrar) cəmi **$0.000362** xərclədi, 4 LLM sorğusu göndərildi. Təkrar sual cache-dən
qaytarıldı: 1 sorğuya (20%) qənaət edildi.
