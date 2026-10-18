# عقد العرض — الإصدار 0 (مسودة M5، ADR-0019)

مسودة تخطيط: تُجمَّد كإصدار 1 عند إغلاق حزمتها (WP-32 الجزء أ، WP-34 الجزء ب) بدليل CI؛ ما لم يُنفَّذ منها لا يُعدّ مدعومًا.

## أ. الإطار وكائن العرض (WP-32)

- **الإطار**: ما يحدده firmware عبر `EFI_GRAPHICS_OUTPUT_PROTOCOL` قبل EBS (UEFI 2.11 §12.9): القاعدة الفيزيائية، الحجم، العرض والارتفاع، البكسلات لكل سطر (stride)، صيغة البكسل؛ المدعوم في M5: `PixelRedGreenBlueReserved8BitPerColor` و`PixelBlueGreenRedReserved8BitPerColor` (32 بت)؛ غير ذلك يُعلن الإطار غائبًا (`present=0`) ولا يُحتسب فشل إقلاع. لا تغيير لوضع الفيديو.
- **النواة**: ترسم الإطار في نافذة MMIO الخاصة بسمة write-combining إن أتاحتها PAT وإلا uncached؛ سطر الإقلاع `kernel|display|present=…|w=…|h=…|stride=…|format=…|bytes=…|pattern=…|code=ok|selfcheck=…` بعد رسم نمط تشخيصي ثابت (أربع زوايا بألوان معلومة + شريط بصمة build) — لا يُحتسب سطح مكتب (§9).
- **الكائن** `Object::Display` (النوع 10): وحيد، تسلّمه النواة لمدير الخدمات ويوجَّه إلى الخدمة `display` (services.md v1.4)؛ `display_info(h, out)` (ABI v1.8: 32 بايت: w, h, stride, format, bytes) و`display_map(h)` يعيد مقبض VMO فيزيائي يغطي الإطار (إطاراته ثابتة لا تُحرَّر) — الحقوق `READ|WRITE|MAP|DUP|TRANSFER`.
- **خرائط المستخدم** (ABI v1.8، ipc.md v1.1): `vmo_map(h, prot) → addr` (حق MAP؛ `prot` ⊆ حقوق المقبض READ/WRITE؛ لا تنفيذ؛ المنطقة فوق صورة التطبيق تختارها النواة بحجم VMO)، `vmo_unmap(addr) → 0`؛ حد 64 خريطة لكل عملية؛ تزول مع العملية. الـ VMO العادي (إطارات مخصصة) يُرسم بسمة عادية؛ الفيزيائي بسمة write-combining/uncached.
- **المختبر**: `screendump` عبر مراقب QEMU إلى PPM؛ `tools/screen.py regions IMG spec.json` يفحص ألوان مناطق مسماة (متوسط اللون ± سماحية) ويعيد بصمة؛ كل حالة عرض تطبع تسلسليًا ما رُسم فيقارنه المضيف.

## ب. الخدمة `display` (compositor ومدير النوافذ، WP-34)

- **الأسطح**: العميل ينشئ VMO بحجم `w×h×4` ويرسل `CREATE_SURFACE <w> <h>` + نسخة مقبض VMO (بحق READ|MAP فقط) → `OK <surface>`؛ `COMMIT <surface> <x> <y> <w> <h>` يعلن منطقة تغيّرت (تُركَّب في المخزن الخلفي ثم تُنقل إلى الإطار بإيقاع النبضة ≤ 60 Hz)؛ `DESTROY <surface>`؛ إغلاق قناة العميل يزيل أسطحه ونوافذه.
- **النوافذ**: `CREATE_WINDOW <surface> <title…>` → `OK <window>`؛ الزخرفة (شريط العنوان، إغلاق، تصغير) يرسمها الـ compositor؛ ترتيب z بالتركيز؛ `RESIZE`/`MOVE` من المؤشر أو لوحة المفاتيح؛ العميل يُبلَّغ `RESIZED <window> <w> <h>` ويعيد CREATE_SURFACE بالحجم الجديد ثم `ATTACH`؛ `MINIMIZE`/`RESTORE`.
- **الأحداث** إلى العميل على قناته (طابور 64 حدثًا؛ الفائض يُسقط ويُعدّ): `KEY <code> <down/up> <mods> <char>`، `POINTER <x> <y> <buttons>`، `FOCUS`/`UNFOCUS`، `RESIZED`، `CLOSE_REQUESTED`. مصدر أحداث المفاتيح خدمة `input` بتوجيه الجلسة (input.md v2)؛ الـ compositor لا يرى المفاتيح أثناء القفل.
- **عدم الاستجابة**: لا انتظار على عميل؛ طابور ممتلئ 2000 نبضة → النافذة تُعلَّم «لا يستجيب» في الزخرفة ويمكن إغلاقها من الزخرفة (تُسقط أسطحها).
- **القفل**: `LOCKED`/`UNLOCKED` من خدمة `session` (برمزها): أثناء القفل يُعرض سطح الجلسة وحده وتُحجب كل النوافذ؛ عند بدء الـ compositor يسأل `session` `STATE` قبل عرض أي شيء.
- **الاختبارات الحاكمة**: TST-M5-DISPLAY-BOOT، TST-M5-SCREEN، TST-M5-WINDOW-STATES، TST-M5-APP-HANG.
