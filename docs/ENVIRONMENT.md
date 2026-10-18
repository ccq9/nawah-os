# ENVIRONMENT — فحص المضيف (M0)

تاريخ الفحص: 2026-10-17 (UTC). الوضع: MODE: EXECUTE. البرومبت الحاكم: OS-EXEC-AR 3.2، sha256 = e8318ae46ae45d33cb6a62fb4b54c32afec8bd605ac59454c52bd0866c33a620، محفوظ في docs/prompt/OS-EXEC-AR-v3.2.md.

## المضيف

- نظام: Linux 6.18.44-fc-v139 x86_64 (Ubuntu 24.04 userland)، مساحة سحابية خاصة بالجلسة.
- موارد: 2 vCPU، 7–8 GiB ذاكرة، نحو 30 GiB حرة. لا /dev/kvm (TCG فقط؛ لا يبطل المحاكاة، يبطئها).
- جذر المشروع: /home/claude/nawah-os. مستودع Git محلي، فرع main. لا مستودع بعيد (انظر العوائق).
- الصلاحيات: root داخل المساحة؛ apt يعمل لمستودعات Ubuntu؛ الشبكة عبر وكيل بقائمة سماح.

## الأدوات (قيم من تشغيل فعلي)

| أداة | الإصدار | حالة |
|---|---|---|
| clang | Ubuntu clang 18.1.3 | متاح |
| lld-link / ld.lld | LLD 18.1.3 | متاح |
| gcc | 13.3.0 | متاح (غير مستعمل لأول بناء) |
| rustc / cargo | 1.97.0 | متاح، لكن هدف x86_64-unknown-uefi غير مثبت |
| rustup | 1.28.2 | تنزيل الهدف مرفوض شبكيًا |
| python3 | 3.13.16 | متاح (مشغّل tools/project.py) |
| git | 2.43.0 | متاح |
| gdb | 15.1 | متاح |
| qemu-system-x86_64 | 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18) | ثُبّت في هذا الفحص عبر apt |
| OVMF (edk2) | 2024.02-2ubuntu0.10 | ثُبّت؛ CODE sha256 ad23261d…cb083، VARS sha256 5d2ac383…5d1e |
| mtools | 4.0.43 | ثُبّت |
| dosfstools | مثبت | متاح |
| qemu-system-aarch64 | — | غير مثبت (يلزم لتجربة النقل المبكرة لاحقًا) |

## الناقص وأثره وخطوة المعالجة

1. هدف Rust x86_64-unknown-uefi: التنزيل من static.rust-lang.org مرفوض من الوكيل («unsuccessful tunnel»). الأثر: مسار Rust لأول بناء BLOCKED. المعالجة: السماح الشبكي لذلك النطاق، أو توفير rust-std للهدف يدويًا. القرار المؤقت: C عبر clang + lld-link (شجرة البند 18، الفرضية الثانية) — انظر docs/adr/0001-bootstrap.md.
2. مستودع بعيد: رمز GitHub في البيئة غير صالح؛ لا يمكن إنشاء مستودع من هنا. الأثر: النمط durable غير متاح؛ العمل محفوظ محليًا داخل الجلسة فقط. المعالجة: ينشئ المستخدم مستودعًا خاصًا فارغًا ويرسل رابطه، ثم يُربط ويُدفع إليه.
3. KVM: غير متاح. الأثر: تشغيل TCG أبطأ؛ لا أثر على صحة الاختبارات.
4. qemu-system-aarch64: غير مثبت. يُثبت عند بدء تجربة النقل المبكرة (M2–M3).

## أوامر التشغيل الفعلية

- التحقق: python3 tools/project.py validate-records
- البناء: python3 tools/project.py build --target pc-qemu
- الإقلاع: python3 tools/project.py boot --target pc-qemu
- الاختبار: python3 tools/project.py test --target pc-qemu --suite M1
- الحالة: python3 tools/project.py status --json

(تُستكمل الأوامر عند تنفيذ كل واجهة؛ لا يُدرج أمر قبل أن يعمل.)

## نمط التشغيل

- development_worker: interactive (الوكيل في هذه الجلسة). لا مشغّل دائم متحقق.
- verification_runner: غير مهيأ بعد؛ يتوقف على المستودع البعيد.

## خطاف ما قبل الالتزام

`cp tools/hooks/pre-commit .git/hooks/pre-commit` — يرفض أي commit لا تمر سجلاته بـ `validate-records` (0 أخطاء). أُضيف 2026-10-18 بعد أن أخفى أنبوب `| tail` حالة خروج المدقق مرتين.
