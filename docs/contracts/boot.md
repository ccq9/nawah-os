# عقد الإقلاع وتسليم التحكم (M1) — boot.md

الإصدار: 1.0 (M0). المرجع: UEFI 2.11 §7.4.6 (ExitBootServices/GetMemoryMap) [S18]، §4 (System Table)، [S31] (PE/COFF subsystem EFI application).

## السلسلة

firmware (OVMF) → EFI/BOOT/BOOTX64.EFI (صورة النواة الواحدة، PE32+) → `efi_main(ImageHandle, SystemTable)` → مرحلة `pre_ebs` → ExitBootServices → مرحلة `post_ebs` (النواة) → [M2+] الخدمات.

## المدخلات والمخرجات

- مدخل: ImageHandle، EFI_SYSTEM_TABLE صالح (Hdr.Signature = 0x5453595320494249).
- مخرج pre_ebs → post_ebs: بنية `boot_info` مملوكة للنواة في ذاكرة EfiLoaderData محجوزة قبل EBS، تحتوي: magic، version، build_id (ASCII)، memory_map (مؤشر، size، descriptor_size، descriptor_version، map_key المستعمل في EBS الناجح)، framebuffer (اختياري في M1: غائب يُعلن غيابه)، rsdp (العنوان الفيزيائي لـ RSDP من جدول تهيئة EFI — GUID ACPI 2.0 ثم 1.0 — أو 0 إن غاب؛ يُملأ منذ WP-10)، runtime_services (مؤشر).
- وحدات وأحجام: خريطة الذاكرة تُطلب بحجم 0 أولًا لمعرفة الحجم، ويُخصص الحجم + 2×descriptor_size (المواصفة تحذر أن التخصيص نفسه قد يغير الخريطة). الحد الأقصى المقبول للخريطة في M1: 64 KiB؛ تجاوزه خطأ موثق BOOT_E_MAP_TOO_LARGE.

## الملكية والصلاحية بعد التسليم

- بعد نجاح EBS: Boot Services غير صالحة ولا تُستدعى؛ Runtime Services تبقى صالحة (لا تُستعمل في M1). ConOut غير صالح. الذاكرة من نوع EfiLoaderCode/LoaderData/BootServices* تعود للنواة وفق الخريطة؛ EfiRuntimeServices* وACPI NVS محجوزة.
- إنفاذ بنيوي: شيفرة post_ebs في وحدة ترجمة مستقلة (kernel/) لا تتضمن تعريف EFI_BOOT_SERVICES ولا تستقبل مؤشر SystemTable؛ تستقبل boot_info فقط. اختبار TST-M1-NOBS يفحص ذلك ساكنًا.

## الحالات والانتقالات

start → map_acquired → ebs_attempted → (success → post_ebs | retry once with fresh map → success | fail → halt_diag).
إعادة المحاولة: عند EFI_INVALID_PARAMETER (map_key قديم) تُعاد GetMemoryMap مرة واحدة ثم EBS؛ فشل ثانٍ = فشل تسليم.

## الأخطاء والتشخيص

كل فشل يصدر سطر `OSX|<build_id>|boot|error|code=<name>|status=<hex>` ثم `halt` (cli; hlt) دون إعادة تشغيل. في المختبر يُسبق الـhalt بخروج isa-debug-exit برمز 0x30 (QEMU exit 97). رموز: BOOT_E_BAD_TABLE، BOOT_E_MAP_TOO_LARGE، BOOT_E_ALLOC، BOOT_E_EBS_FAILED.

## عقد الأثر التسلسلي

أسطر ASCII على COM1: `OSX|<build_id>|<component>|<event>|k=v|...`. أول سطر: `OSX|<build_id>|boot|start|...`. سطر النجاح الحاكم في M1: `OSX|<build_id>|kernel|post_ebs|map_key=<hex>|descriptors=<n>` يصدر من kernel/ بعد EBS. رمز خروج النجاح في المختبر 0x10 (QEMU exit 33).

## المهلات والإلغاء

لا مهلة داخل الضيف في M1؛ المختبر يقطع بعد 180 ثانية ويعتبر التعليق FAIL.

## التوافق والإصدار

boot_info.version = 1. أي تغيير في الحقول يرفع الإصدار ويعيد فتح أدلة M1.

## اختبارات الإنفاذ

TST-M1-BUILD، TST-M1-BOOT، TST-M1-NOBS، TST-M1-NEG (حقن فشل EBS)، TST-M1-INVALID-IMAGE (N/A حتى فصل المحمل).
