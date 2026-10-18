# عقد المصادقة والجلسات — الإصدار 1 (WP-25، ADR-0016 §3 و§5؛ فوق syscall.md v1.5 وservices.md v1.1)

مجمَّد (أُغلق WP-25 بدليل CI run 39133153681): أي تغيير في الكائنات أو النداءات أو الرسائل = إصدار جديد مع سجل قرار. الكود: `user/nawah-crypto` (SHA-256/HMAC/PBKDF2)، `user/apps/authd` (الخدمة `auth`)، `kernel/src/object/token.rs` (الرمز والسلطة)، `kernel/src/syscall/mod.rs` (النداءات 24–26)، `tools/project.py` (قاعدة مستخدمي المختبر).

## 1. الكائنات (النواة)

- **السلطة** `Object::Authority`: مقدرة سكّ الرموز. تُنشأ مرة واحدة عند الإقلاع وتُسلَّم لمدير الخدمات مقبضًا أوليًا ثانيًا (`rdi + 1`)، وهو يسلّمها للخدمة المسماة `auth` وحدها مقبضًا أوليًا ثانيًا لها (services.md §4). حقوقها `DUPLICATE|TRANSFER`. لا تُستنسخ في النواة بعد الإقلاع.
- **الرمز** `Object::Token{uid, gid, perms, expires}`: مقبض الساكّ بحقوق `WRITE|DUPLICATE|TRANSFER`؛ ما يُسلَّم للعميل نسخة **بلا WRITE** فلا يستطيع إبطاله ولا تصعيده. `expires` بالنبضات (0 = بلا انتهاء). الحالة: `revoked` (أُبطل) و`expired` (`clock_ticks() ≥ expires`).
- الصلاحيات (بتات `perms`): `ADMIN=1`، `CONFIG_WRITE=2`، `NET=4`، `SHELL=8`.

## 2. النداءات (ABI v1.5، إضافي)

| الرقم | الاسم | الوسائط | النتيجة |
|---|---|---|---|
| 24 | `token_create` | authority_h, uid, gid, perms, expires | مقبض رمز (حقوق الساكّ)؛ مقبض ليس سلطةً → `ERR_ACCESS` (انعدام السلطة فشلُ وصول، لا نوع) |
| 25 | `token_info` | h, out_ptr (32 بايت قابلة للكتابة) | 0؛ يكتب `uid u32, gid u32, perms u32, flags u32 (bit0 revoked, bit1 expired), expires u64, id u64` لأي حامل؛ `id` هوية الرمز (تتساوى لنسختين من الرمز نفسه وتختلف بين الرموز؛ بها تميّز الخدمة جلسة من أخرى) |
| 26 | `token_revoke` | h | 0؛ يتطلب `WRITE` على المقبض (`ERR_ACCESS`)؛ الإبطال نهائي ويظهر لكل النسخ |

## 3. قاعدة المستخدمين `/SYSTEM/USERS.DB`

- نص ASCII؛ السطر الأول `NAWAH-USERS 1`؛ ثم سطر لكل مستخدم `uid:gid:name:perms:iterations:salt_hex:hash_hex`؛ `#` تعليق.
- الاشتقاق: `hash = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)` (RFC 8018 §5.2؛ RFC 7914 §11 للمتجهات)؛ الملح 16 بايت (NIST SP 800-132 §5.1: ≥ 128 بت)؛ التكرارات مخزَّنة لكل مستخدم: المختبر 20000 (سرعة TCG)، الافتراضي للمنتج 600000. المقارنة بزمن ثابت (`ct_eq`).
- قاعدة المختبر يولّدها `tools/project.py` بـ `hashlib.pbkdf2_hmac` (تنفيذ مستقل عن `nawah-crypto`): `admin` (uid 1000، perms ADMIN|CONFIG_WRITE|NET|SHELL) و`user` (uid 1001، perms SHELL) بكلمتي مرور المختبر الموثقتين في `platform/pc-qemu/target.json`. لا كلمة مرور ولا ملح ولا تجزئة في أي سطر تشخيصي؛ فحص المضيف يبحث عن كلمة المرور في الصورة الخام كلها ويجب ألا يجدها.
- إنشاء المستخدمين وتغيير كلمات المرور داخل النظام (يحتاج مصدر عشوائية للملح) خارج WP-25 — M5 (مُسجَّل في ADR-0016 «ما لم يُحسم»).

## 4. الخدمة `auth` (`/SYSTEM/AUTHD.ELF`)

تُدار بمدير الخدمات؛ العملاء يصلونها بـ `CONNECT auth` (services.md §3). رسائل ASCII على قناة العميل، ردٌّ واحد لكل طلب:

| الطلب | الردّ |
|---|---|
| `LOGIN <name> <password>` | `OK <uid> <gid> <perms>` + مقبض رمز (بلا WRITE، ينتهي بعد `SESSION_TICKS` = 3,600,000 نبضة)؛ `ERR ACCESS` (اسم أو كلمة مرور خاطئة — الرسالة نفسها للحالتين)؛ `ERR DELAYED <ticks>` بعد 5 إخفاقات متتالية على الاسم نفسه حتى تمضي 2000 نبضة من آخر إخفاق (العدّاد يُصفَّر بالنجاح) |
| `WHOAMI` + مقبض رمز | `OK <uid> <gid> <perms>`؛ رمز مُبطَل/منتهٍ/ليس رمزًا → `ERR ACCESS` |
| `LOCK` + مقبض رمز | `OK`: يُبطل الرمز ويُبقي الجلسة مقفولة (uid) |
| `UNLOCK <password>` + مقبض الرمز المقفول | `OK <uid> <gid> <perms>` + رمز جديد إن صحّت كلمة المرور لمستخدم الرمز؛ `ERR ACCESS`؛ الحدّ والتأخير كما في LOGIN |
| `LOGOUT` + مقبض رمز | `OK`: يُبطل الرمز وينهي الجلسة (لا UNLOCK بعدها: `ERR ACCESS`) |
| غير ذلك | `ERR BAD_REQUEST` |

الخدمة لا تثق بما تفحصه الواجهة: كل طلب يحمل الرمز يُفحص بـ `token_info` (مُبطَل/منتهٍ → `ERR ACCESS`). الطلب بلا مقبض حيث يلزم → `ERR BAD_REQUEST`. الطلب الذي يحمل أكثر من مقبض يُرفض.

## 5. الاختبارات الحاكمة

TST-M4-HASH-VECTORS (مضيف: `cargo test -p nawah-crypto`؛ ضيف: `authd` يطبع `auth|kat|fails=0|pbkdf2_80000=1` عند بدئه)، TST-M4-TOKEN-OBJECTS (وحدة نواة: السكّ بالسلطة فقط، `token_info`، نسخة بلا WRITE لا تُبطل، الإبطال يظهر للنسخ كلها، الانتهاء بالساعة)، TST-M4-LOGIN (دخول صحيح يعطي رمزًا بصلاحيات المستخدم، خاطئ `ERR ACCESS`، 5 إخفاقات ثم `ERR DELAYED` حتى للكلمة الصحيحة ثم نجاح بعد المهلة؛ فحص المضيف: لا كلمة مرور في الصورة الخام)، TST-M4-SESSION-LOCK (LOCK ثم WHOAMI بالرمز القديم `ERR ACCESS` ثم UNLOCK بكلمة المرور يعطي رمزًا جديدًا بالهوية نفسها؛ LOGOUT ثم WHOAMI/UNLOCK `ERR ACCESS`).
