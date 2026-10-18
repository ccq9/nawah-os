# عقد مدير الخدمات — الإصدار 0 (مسودة M4، ADR-0016)

مسودة تخطيط: تُجمَّد كإصدار 1 عند إغلاق حزمتها بدليل CI؛ ما لم يُنفَّذ منها لا يُعدّ مدعومًا.

- **البيان** `/SYSTEM/SERVICES.TXT`: سطر لكل خدمة `name path deps timeout_ticks restart max_restarts backoff_ticks`؛ التبعيات بأسماء مفصولة بفواصل أو `-`؛ `restart` ∈ {never, on-failure}.
- **قناة الإقلاع**: كل خدمة تستلم في `rdi` مقبض قناة إلى svcmgr وترسل عليها `READY` (4 بايت ASCII) قبل مهلتها؛ بعدها تُستعمل القناة للتحكم (`STOP`).
- **قناة التحكم** (المختبر/الـshell): طلب `LIST` → ردّ نصي سطر لكل خدمة `name state restarts`؛ الحالات: `pending`, `starting`, `ready`, `failed`, `given_up`, `stopped`.
- **إعادة التشغيل**: عند خروج غير صفري أو إنهاء بخطأ وسياسة `on-failure`: محاولة بعد `backoff × 2^n` حتى `max_restarts` ثم `given_up`.
- **الأخطاء**: دورة في التبعيات = `MANIFEST_CYCLE`، مسار مفقود = `SPAWN_FAILED`، مهلة = `failed`.
