# عقد الإقلاع وتسليم التحكم (M1) — boot.md

الإصدار: 1.1 (1.0 في M0؛ 1.1 في WP-45: نمط الإقلاع، §«نمط الإقلاع» أدناه — إضافي، `boot_info.version` يبقى 1). المرجع: UEFI 2.11 §7.4.6 (ExitBootServices/GetMemoryMap) [S18]، §4 (System Table)، [S31] (PE/COFF subsystem EFI application).

## السلسلة

firmware (OVMF) → EFI/BOOT/BOOTX64.EFI (صورة النواة الواحدة، PE32+) → `efi_main(ImageHandle, SystemTable)` → مرحلة `pre_ebs` → ExitBootServices → مرحلة `post_ebs` (النواة) → [M2+] الخدمات؛ (v1.1) → نمط الإقلاع → مدير الخدمات ببيان النمط (services.md v1.11).

## المدخلات والمخرجات

- مدخل: ImageHandle، EFI_SYSTEM_TABLE صالح (Hdr.Signature = 0x5453595320494249).
- مخرج pre_ebs → post_ebs: بنية `boot_info` مملوكة للنواة في ذاكرة EfiLoaderData محجوزة قبل EBS، تحتوي: magic، version، build_id (ASCII)، memory_map (مؤشر، size، descriptor_size، descriptor_version، map_key المستعمل في EBS الناجح)، framebuffer (اختياري في M1: غائب يُعلن غيابه؛ منذ WP-32 يُملأ من GOP قبل EBS: القاعدة والعرض والارتفاع والبكسلات لكل سطر وصيغة البكسل 0/1، و`present` — display.md أ)، rsdp (العنوان الفيزيائي لـ RSDP من جدول تهيئة EFI — GUID ACPI 2.0 ثم 1.0 — أو 0 إن غاب؛ يُملأ منذ WP-10)، runtime_services (مؤشر).
- وحدات وأحجام: خريطة الذاكرة تُطلب بحجم 0 أولًا لمعرفة الحجم، ويُخصص الحجم + 2×descriptor_size (المواصفة تحذر أن التخصيص نفسه قد يغير الخريطة). الحد الأقصى المقبول للخريطة في M1: 64 KiB؛ تجاوزه خطأ موثق BOOT_E_MAP_TOO_LARGE.

## الملكية والصلاحية بعد التسليم

- بعد نجاح EBS: Boot Services غير صالحة ولا تُستدعى؛ Runtime Services تبقى صالحة (لا تُستعمل في M1). ConOut غير صالح. الذاكرة من نوع EfiLoaderCode/LoaderData/BootServices* تعود للنواة وفق الخريطة؛ EfiRuntimeServices* وACPI NVS محجوزة.
- إنفاذ بنيوي: شيفرة post_ebs في وحدة ترجمة مستقلة (kernel/) لا تتضمن تعريف EFI_BOOT_SERVICES ولا تستقبل مؤشر SystemTable؛ تستقبل boot_info فقط. اختبار TST-M1-NOBS يفحص ذلك ساكنًا.

## الحالات والانتقالات

start → map_acquired → ebs_attempted → (success → post_ebs | retry once with fresh map → success | fail → halt_diag).
إعادة المحاولة: عند EFI_INVALID_PARAMETER (map_key قديم) تُعاد GetMemoryMap مرة واحدة ثم EBS؛ فشل ثانٍ = فشل تسليم.

## نمط الإقلاع (v1.1، WP-45، 2026-11-09 — قرار مسجَّل، لا إضعاف اختبار)

القرار: docs/PLAN-ANSWER.md §2.1 (K1 بحراسة) و§5.3 البندان 5 و6؛ يحسم «الإقلاع التفاعلي» في ADR-0019 (ما لم يُحسم). صورة واحدة `NAWAH.EFI` لها نمطان يُحسمان وقت التشغيل في النواة بعد EBS؛ لا شيفرة جديدة قبل EBS ولا صورة رابعة (رُفض بناء صورة فحص ذاتي مستقلة لأنه يُخرج حكم TST-M1-BOOT من الصورة المشحونة، ورُفض قراءة المفتاح قبل EBS لأنه يضيف unsafe في `boot/` وملفًا على ESP قد يتسرب إلى صورة موزعة).

- **النمطان**: `interactive` (الافتراضي): الإقلاع إلى شاشة الدخول ببيان النظام `/SYSTEM/SERVICES.TXT`؛ و`selftest`: الفحص الذاتي للمختبر ببيان `/SYSTEM/SELFTEST.TXT` ثم الخروج كما في M1.
- **الاختيار، بهذا الترتيب، وكل خطوة لا تتم إلا إن نجحت سابقتها**:
  1. بوابة المحاكي: البت `CPUID.1:ECX[31]`. إن كان صفرًا لا يُلمس أي منفذ fw_cfg، والنمط `interactive`.
  2. توقيع fw_cfg يساوي `QEMU`. غير ذلك → `interactive`.
  3. ملف fw_cfg باسم `opt/nawah/selftest` قيمته بالضبط البايت `1`. هذا وحده يعطي `selftest`.
- **كل ما عدا ذلك `interactive`**: غياب الملف، أو أي قيمة أخرى (ومنها `0` و`1` متبوعًا بأي بايت)، أو اسم مفتاح نواة الاختبار `opt/nawah/test` بأي قيمة: وجوده وحده لا يغيّر النمط، وصورة الإصدار لا تحوي حالات ktest (الميزة `ktest` خارجها).
- **المفتاح يختار ولا يحمل**: لا مسار ولا اسم بيان ولا امتياز في قيمته؛ يختار بين البيانين الثابتين في النواة وحدهما (services.md v1.11 §0.000).
- **سطر الأثر**: سطر واحد بالضبط (المختبر يعدّه: `max_counts` و`min_counts` للعلامة `|kernel|boot_mode|` تساويان عدد الإقلاعات في الحالة: 1 في TST-M1-BOOT و6 في TST-M6-INTERACTIVE-BOOT، لأن العدّ على مستوى الحالة يجمع مراحلها): `OSX|<build_id>|kernel|boot_mode|mode=<selftest|interactive>|source=<fw_cfg|none>|key=<ok|absent|invalid>|hv=<0|1>`. `source=fw_cfg` و`key=ok` معًا إن وفقط إن كان النمط `selftest`. `key=invalid`: الملف موجود وقيمته ليست `1`. `key=absent`: لم يُقرأ ملف (البت صفر، أو لا توقيع، أو لا ملف بالاسم)؛ `hv=0` يميّز أول هذه الثلاثة، والثاني والثالث لا يتميزان في الأثر (حدّ معلن).
- **مسار `selftest`**: كما في M1 دون تغيير غير البيان: يُحمَّل `SELFTEST.TXT` (`reply=OK 0|code=ok|selfcheck=1`)، ثم يتوقف المؤقت، ثم `kernel|m1_done|exit=0x10` والخروج برمز QEMU 33.
- **مسار `interactive`**: المؤقت يبقى عاملًا؛ يُحمَّل `SERVICES.TXT` (`reply=OK 8`)؛ ثم تنتظر النواة بلا نهاية ولا تطبع `m1_done` ولا تكتب إلى منفذ الخروج 0xF4. إن فشل بدء المدير أو كان ردّه غير `OK <n>` يصدر سطر `kernel|svcmgr` بـ `selfcheck=0` ثم `halt` دون كتابة إلى 0xF4 — فشل معلن لا نجاح كاذب. (`halt` يوقف المعالج الإقلاعي وحده؛ وكل عمليات المستخدم تُنشأ على هذا المعالج وخيوطها مثبتة عليه (sched)، فلا يبقى ما يعمل ولا تظهر شاشة دخول؛ إيقاف المعالجات الأخرى صراحةً بند لاحق. هذا الفرع بلا حالة مختبر في WP-45، ويُختبر في WP-67 (مقترحة) بقرص بيانه تالف. ومهلة `OK 8` البالغة 2000 نبضة تشمل بدء أربع خدمات قبل الرد، فعلى مضيف بطيء يفشل الإقلاع بـ`selfcheck=0` ثم يتوقف بلا رسالة مرئية؛ تُقرأ `wait_ticks` على CI، ورسالة التوقف المرئية ومهلة LOAD التفاعلية في WP-67.)
- **حراسة 0xF4 خارج هذا الإصدار**: البوابة تحرس قراءة fw_cfg وحدها. مسارات الذعر ما زالت تكتب رمز الخروج (QEMU 35)، والخروج قبل EBS (QEMU 97، `boot/stub.rs`) لا يقرأ fw_cfg؛ حراسة 0xF4 في كل المسارات بند قبل Beta مسجَّل خطرًا (PLAN-ANSWER §5.3 البند 6).
- **البوابة تُقاس أولًا**: البت تحت TCG بـ `cpu=qemu64` في المختبر غير مقيس عند كتابة v1.1؛ يقيسه سطر `boot_mode` نفسه على CI: `hv=1` مطلوب في TST-M1-BOOT وفي المرحلة الأولى من TST-M6-INTERACTIVE-BOOT، فإن كان صفرًا فشلا صراحةً. إن كان صفرًا تُستبدل الخطوة 1 بمعرّف OEM في ACPI (البديل المسجَّل) ويُعدَّل هذا القسم قبل إغلاق WP-45. SMBIOS غير مختار.
- **حدّ معلن (قرص المختبر)**: الإقلاع التفاعلي على قرص مختبر بحسابات معروفة وملح ثابت؛ غير صالح لعتاد حقيقي ولا صورة إصدار (RSK-017). صورة release بلا حسابات المختبر وحارسها يُكتبان في أول هدف release.
- **أنماط فشل معلنة**: (1) آلة إنتاجية تحت QEMU يُمرَّر لها المفتاح تُجري الفحص الذاتي وتخرج — أثر على التوفر وحده، ومن يملك سطر أوامر المشرف يملك الضيف. (2) مشرف غير QEMU يضيء البت: تُكتب قيمة الاختيار إلى منفذ fw_cfg (0x510) قبل فحص التوقيع؛ أثره غير متحقق. (3) بت غير معروض تحت TCG: TST-M1-BOOT يقلع تفاعليًا فيفشل بالمهلة — فشل صاخب لا مرور كاذب.
- **أوراكل M1 تحت المفتاح**: TST-M1-BOOT يُشغَّل بـ `-fw_cfg name=opt/nawah/selftest,string=1` ويطلب زيادةً على أوراكله سطر `kernel|boot_mode|mode=selftest|source=fw_cfg|key=ok|`؛ `reply=OK 0` و`code=ok` و`selfcheck=1` ورمز الخروج 33 كما هي، والبيان `/SYSTEM/SELFTEST.TXT` بدل `/SYSTEM/SERVICES.TXT` تغيير مسار معلن. TST-M1-NEG دون تعديل (يخرج بـ 97 قبل EBS). TST-M1-NOBS دون تعديل: منطق النمط في وحدة خارج `kmain.rs`. سياسة unsafe: لا أسطر جديدة (`tools/unsafe-baseline.txt` يبقى 186).

## الأخطاء والتشخيص

كل فشل يصدر سطر `OSX|<build_id>|boot|error|code=<name>|status=<hex>` ثم `halt` (cli; hlt) دون إعادة تشغيل. في المختبر يُسبق الـhalt بخروج isa-debug-exit برمز 0x30 (QEMU exit 97). رموز: BOOT_E_BAD_TABLE، BOOT_E_MAP_TOO_LARGE، BOOT_E_ALLOC، BOOT_E_EBS_FAILED.

## عقد الأثر التسلسلي

أسطر ASCII على COM1: `OSX|<build_id>|<component>|<event>|k=v|...`. أول سطر: `OSX|<build_id>|boot|start|...`. سطر النجاح الحاكم في M1: `OSX|<build_id>|kernel|post_ebs|map_key=<hex>|descriptors=<n>` يصدر من kernel/ بعد EBS. رمز خروج النجاح في المختبر 0x10 (QEMU exit 33).

## المهلات والإلغاء

لا مهلة داخل الضيف في M1؛ المختبر يقطع بعد 180 ثانية ويعتبر التعليق FAIL. (v1.1) نمط `interactive` لا يخرج بتصميمه: حالة المختبر عليه تنتهي بإنهاء المختبر نفسه بعد أن يتم أوراكلها، والمهلة تبقى FAIL.

## التوافق والإصدار

boot_info.version = 1. أي تغيير في الحقول يرفع الإصدار ويعيد فتح أدلة M1.

## اختبارات الإنفاذ

TST-M1-BUILD، TST-M1-BOOT، TST-M1-NOBS، TST-M1-NEG (حقن فشل EBS)، TST-M1-INVALID-IMAGE (N/A حتى فصل المحمل). (v1.1) TST-M1-BOOT تحت مفتاح الفحص الذاتي؛ TST-M6-INTERACTIVE-BOOT (بلا مفتاح: `mode=interactive|source=none` و`hv=1`، ولا `kernel|m1_done|` ولا `|ktest|` ولا `selfcheck=0`؛ ومراحله السلبية: `opt/nawah/selftest=0` → `key=invalid` وإقلاع تفاعلي، `opt/nawah/test=exc_de` → `source=none` ولا `|ktest|start|`، وقيمة المفتاح `svc-sh` → إقلاع تفاعلي يحمّل `SERVICES.TXT` (`reply=OK 8`) لا `SVC-SH.TXT` (بيان النظام نفسه يضع `sh` على COM2، فالفاصل هو علامة البيان لا أثر الصدفة)، وقيمة `10` → `key=invalid`، وبلا بت المشرف `-cpu qemu64,-hypervisor` مع المفتاح → إقلاع تفاعلي بلا كتابة إلى 0xF4)؛ TST-M0-003 (اسم المفتاح في `target.json` هو ما تقرؤه النواة نصًا).
