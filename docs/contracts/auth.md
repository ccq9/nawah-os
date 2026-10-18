# عقد المصادقة والجلسات — الإصدار 0 (مسودة M4، ADR-0016)

مسودة تخطيط: تُجمَّد كإصدار 1 عند إغلاق حزمتها بدليل CI؛ ما لم يُنفَّذ منها لا يُعدّ مدعومًا.

- **التخزين** `/SYSTEM/USERS.DB`: نصي، سطر لكل مستخدم `uid:gid:name:perms:iterations:salt_hex:hash_hex`، إصدار مخطط في السطر الأول `NAWAH-USERS 1`.
- **الاشتقاق**: PBKDF2-HMAC-SHA256، ملح 16 بايت عشوائي، 600000 تكرار، مخرج 32 بايت (RFC 8018 §5.2، NIST SP 800-132).
- **الطلبات** (قناة auth): `LOGIN name password` → مقبض Token أو `ERR_ACCESS`؛ بعد 5 إخفاقات متتالية تأخير 2 ثانية لكل محاولة؛ `LOCK token`, `UNLOCK token password`, `LOGOUT token` (يبطل الرمز)، `WHOAMI token`.
- **الرمز**: كائن نواة `Token{uid, gid, perms, expires}`؛ الصلاحيات بتات: `ADMIN`, `CONFIG_WRITE`, `NET`, `SHELL`؛ `token_info` يعيدها لأي حامل؛ السكّ بمقدرة `Authority` تملكها خدمة auth وحدها.
- **لا يُسجَّل** في أي log: كلمة مرور، ملح، تجزئة.
