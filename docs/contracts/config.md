# عقد التكوين والسياسات — الإصدار 1 (WP-26، ADR-0016 §6؛ فوق auth.md v1 وservices.md v1.1 وfiles.md v1)

يُجمَّد عند إغلاق WP-26 بدليل CI؛ ما لم يُنفَّذ منه لا يُعدّ مدعومًا. الكود: `user/apps/configd` (الخدمة `config`)، `kernel/src/ktest.rs` (الاختبارات الحاكمة)، `tools/fat32.py` (`grep` للفحص على المضيف).

## 1. المخازن والمفاتيح

| المخزن | الملف على الحجم | من يكتب (بالرمز) |
|---|---|---|
| `device` | `/SYSTEM/CFGDEV.A` و`.B` | `CONFIG_WRITE` أو `ADMIN` |
| `policy` | `/SYSTEM/CFGPOL.A` و`.B` | `ADMIN` فقط |
| `user/<uid>` | `/SYSTEM/CFGU<uid>.A` و`.B` (uid < 10000) | رمز بالـ uid نفسه أو `ADMIN` |
| `session` | الذاكرة فقط (يزول بإعادة التشغيل) | أي رمز صالح؛ القيم مفصولة لكل uid |

- المفتاح `[a-z0-9_.]{1,64}`؛ القيمة نص ASCII بلا أسطر ≤ 256 بايت (قد تحوي فراغات)؛ ≤ 64 مفتاحًا لكل مخزن؛ ≤ 8 مخازن مستخدمين محمَّلة في آن.
- **الإصدار** u64 لكل مفتاح: 1 عند الإنشاء ويزيد بكل تعديل ناجح؛ الحذف يزيل المفتاح (إنشاؤه من جديد يبدأ من 1). القراءة تعيد الإصدار مع القيمة.
- **الأسبقية** (`RESOLVE`): `policy` > `user/<uid الرمز>` > `device`؛ الحالة المؤقتة (`session`) لا تدخل في الأسبقية ولا تُحفظ.

## 2. الحفظ (ثبات بلا rename)

ليس في files.md v1 إعادة تسمية، فكل مخزن دائم **خانتان** `.A` و`.B`: الكتابة تذهب إلى الخانة ذات الجيل الأدنى (أو المفقودة؛ أول كتابة إلى `.A`)، بإنشاء/قطع ثم كتابة المحتوى كله ثم `sync`. السطر الأول `NAWAH-CFG 1 <generation> <sha256hex>` حيث التجزئة لبقية الملف؛ ثم سطر لكل مفتاح `key version value`. عند البدء تُقرأ الخانتان ويُعتمد أحدث **سليم** (التجزئة صحيحة)؛ خانة تالفة تُتجاهل بتشخيص `config|store|…|slot=…|bad=1` وتُكتب فوقها في التعديل التالي. لا كتابة في مكان الملف المعتمد أبدًا: انقطاع أثناء الكتابة يترك الخانة الأخرى سليمة.

## 3. الطلبات (قناة عميل عبر `CONNECT config`؛ ردّ واحد لكل طلب)

| الطلب | الردّ |
|---|---|
| `GET <store> <key>` | `OK <version> <value>` أو `ERR NOT_FOUND` |
| `SET <store> <key> <expected_version> <request_id> <value…>` + مقبض رمز | `OK <version>`؛ `ERR VERSION <current>` إن لم يطابق `expected_version` الإصدار الحالي (0 = يجب ألا يكون موجودًا)؛ `ERR ACCESS` (رمز غير صالح أو بلا الصلاحية — §1)؛ `ERR INVALID` (مفتاح/قيمة/مخزن)؛ `ERR FULL`؛ `ERR IO` (فشل الحفظ: لا تغيير في الذاكرة) |
| `DEL <store> <key> <expected_version> <request_id>` + مقبض رمز | كما `SET`؛ `OK <version>` بإصدار المفتاح المحذوف |
| `RESOLVE <key>` + مقبض رمز | `OK <source> <version> <value>` حيث `source` ∈ {policy, user, device} أو `ERR NOT_FOUND` |
| `SUBSCRIBE <store>` + مقبض طرف قناة | `OK`؛ بعدها تصل على تلك القناة رسالة `CHANGED <store> <key> <version>` لكل تعديل **ناجح** (الحذف بإصدار 0)؛ لا شيء للطلبات المرفوضة؛ قناة لا تستقبل (طابور ممتلئ أو مغلقة) تُسقَط |
| `EXPORT <store>` | `OK` ثم سطر لكل مفتاح `key version value` |
| `IMPORT <store> <request_id>` + مقبض رمز، والنص بعد السطر الأول `key value` لكل سطر | `OK <count>`؛ يُرفض كله (`ERR INVALID <line>`) إن كان سطر غير صالح؛ الصلاحيات كـ `SET`؛ كل مفتاح يأخذ إصدارًا جديدًا |
| غير ذلك | `ERR BAD_REQUEST` |

- **`request_id`** (u64 ≠ 0): الخدمة تحفظ لكل قناة عميل آخر 16 نتيجة؛ طلب تعديل يحمل `request_id` سبق → يُعاد الردّ المحفوظ حرفيًا ولا يُطبَّق ثانية (TST-M4-CONFIG-RETRY). 0 = بلا حفظ.
- الرمز يُفحص بـ `token_info` في كل طلب تعديل (مُبطَل/منتهٍ → `ERR ACCESS`) — الخدمة لا تثق بالواجهة (REQ-M4-004). الطلب بلا مقبض حيث يلزم → `ERR BAD_REQUEST`.

## 4. الاختبارات الحاكمة

TST-M4-AUTHZ-DENIED (SET device برمز `user` (SHELL فقط) → `ERR ACCESS` ولا تغيير؛ برمز `admin` → `OK`؛ SET policy برمز CONFIG_WRITE بلا ADMIN → `ERR ACCESS`)، TST-M4-CONFIG-CAS (كاتبان بالإصدار المتوقع نفسه: الثاني `ERR VERSION` والقيمة للأول)، TST-M4-CONFIG-RETRY (`request_id` مكرر: الردّ نفسه والإصدار لا يتقدم)، TST-M4-CONFIG-NOTIFY (`CHANGED` بعد الكتابة، لا شيء بعد الرفض)، TST-M4-POLICY-PRECEDENCE (policy > user > device، وحذف السياسة يعيد قيمة المستخدم)، TST-M4-CONFIG-PERSIST (مرحلتان على الصورة نفسها: القيمة والإصدار بعد إعادة التشغيل؛ `fat32.py grep` يرى السطر في `/SYSTEM/CFGDEV.A`).
