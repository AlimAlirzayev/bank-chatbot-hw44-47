# 2 dəqiqəlik təqdimat

Əvvəlcə demo səhifəsini açın, sonra danışın. Hər hissədə göstərilən düyməni basın.

---

**[0:00] Giriş.** "Son dörd tapşırığı bir layihədə birləşdirdim: bankın müştəri çatbotu. Hər mesaj beş
mərhələdən keçir və hər mərhələ bir tapşırığa uyğundur."

**[0:15] ① Giriş yoxlaması (#44).** *"Hücum (AZ)" düyməsini basın.* "Mesaj modelə göndərilmədən
dayandırıldı. Prompt injection iki üsulla yoxlanır: AZ, EN və RU regex şablonları və Llama Prompt Guard
klassifikatoru. Testdə Prompt Guard EN və RU hücumlarını yaxşı tanıdı, AZ hücumlarında isə zəif idi, ona
görə sonrakı mərhələlərdə də yoxlama var. Kart və telefon nömrəsi [CARD] və [PHONE] ilə maskalanır, model
onları görmür."

**[0:35] ② LLM sorğusu (#45).** *"Əsas model xətası" seçin, "Adi sual" basın.* "Əsas model 429 qaytardı.
Kod 3 dəfə cəhd etdi, 1 və 2 saniyə gözlədi, sonra başqa model ailəsindən olan fallback modelə keçdi.
Hər sorğu costs.csv-yə yazılır, təkrar sual cache-dən qaytarılır. Testlər saxta LLM ilə işləyir, CI uğurla
keçir."

**[0:55] ③ Çıxış yoxlaması və ⑤ DPO datası (#47).** *"Red teaming" seçin, "Adi sual" basın.* "Red teaming
üçün qəsdən təhlükəsiz olmayan system prompt yazdım. gpt-oss-120b onu 5 cəhddən 5-də rədd etdi, qwen isə
təxminən hər 3 cəhddən 1-də CVV istədi. Çıxış yoxlaması belə cavabı müştəriyə göndərmir və DPO cütlüyü
kimi saxlayır: modelin cavabı rejected, təhlükəsiz cavab chosen olur. Etiketi kod təyin edir. Yoxlama
regex əsaslıdır və held-out test dəstində məxfi məlumat tələblərinin təxminən 75–80%-ni tutur. Uzunluq
nisbəti 0.6–1.6 aralığında saxlanılır ki, model cavabın uzunluğunu keyfiyyət əlaməti kimi öyrənməsin."

**[1:25] ④ Loglama (#46).** *Dashboard-u göstərin.* "Hər söhbət logda bir sətirdir. Dərsdəki altı qatlı
çərçivədə təhlükəsizlik qatı yox idi, ona görə `gate_verdict` sahəsini əlavə etdim. Ən zəif mövzu Kart
oldu, səbəbi icazə qaydasıdır: müştəri botunun kartı bloklamaq icazəsi yoxdur. Ən baha model qwen-dir,
xərcin 76%-i ona düşür."

**[1:45] NVIDIA modulları.** "① və ③ NVIDIA-nın input və output rails yanaşmasına uyğundur (NeMo
Guardrails). ④ audit trail və observability-dir. Red teaming rejimi isə Safety, Ethics and Compliance
modulundakı red teaming mövzusuna aiddir."

---

**Mümkün suallar:**
- *"Niyə LLM yox, regex?"* Regex pulsuzdur, sürətlidir və test olunur. Onun buraxdığı halları Prompt
  Guard, modelin özü, çıxış yoxlaması və alət icazələri saxlayır (defense in depth).
- *"Dataset sintetikdir?"* Rejected cavablar qəsdən təhlükəsiz olmayan prompt ilə alınıb, bu red
  teaming-dir. Etiketlər kodla yoxlanılıb və əl ilə oxunub.
- *"Bu dataset nə üçündür?"* `preferences.jsonl` növbəti dərsdə DPO təlimi (TRL `DPOTrainer`) üçün
  istifadə oluna bilər.
