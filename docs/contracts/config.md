# عقد التكوين والسياسات — الإصدار 0 (مسودة M4، ADR-0016)

مسودة تخطيط: تُجمَّد كإصدار 1 عند إغلاق حزمتها بدليل CI؛ ما لم يُنفَّذ منها لا يُعدّ مدعومًا.

- **المخازن**: `device` (`/SYSTEM/CFG/DEVICE.TXT`)، `user/<uid>` (`/SYSTEM/CFG/U<uid>.TXT`)، `session` (ذاكرة فقط)، `policy` (`/SYSTEM/CFG/POLICY.TXT`)؛ مفاتيح ASCII `[a-z0-9_.]{1,64}`، قيم نصية ≤ 256 بايت، كل مفتاح بإصدار u64 يبدأ من 1.
- **الطلبات**: `GET store key` → `value version` أو `ERR_NOT_FOUND`؛ `SET request_id store key value expected_version token` → `version` أو `ERR_VERSION` (التعديل المتزامن) أو `ERR_ACCESS` (الرمز بلا `CONFIG_WRITE`/`ADMIN` للسياسة)؛ `DEL` مثلها؛ `SUBSCRIBE store` بقناة يصلها `CHANGED store key version`؛ `EFFECTIVE key uid` يطبق الأسبقية policy > user > device/default.
- **التكرار**: `request_id` (u64) يُحفظ مع نتيجته لآخر 64 طلبًا لكل عميل؛ الطلب المكرر يعيد النتيجة المحفوظة ولا يغيّر شيئًا.
- **الحفظ**: كتابة إلى `*.TMP` ثم `sync` ثم `unlink` القديم وإعادة التسمية (حتى توفر rename في VFS: نسخة ثم حذف)؛ القراءة عند البدء تتحقق من المخطط وترفض الملف التالف بتشخيص وتبدأ بالافتراضيات.
