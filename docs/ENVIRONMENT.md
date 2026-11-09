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

1. هدف Rust x86_64-unknown-uefi: التنزيل من static.rust-lang.org مرفوض من الوكيل («unsuccessful tunnel»). الأثر (2026-10-17): مسار Rust لأول بناء BLOCKED — رُفع لاحقًا بـ CI (rustup هناك) ثم محليًا بـ build-std (القسم «الفحص المحلي قبل الدفع» أدناه). المعالجة: السماح الشبكي لذلك النطاق، أو توفير rust-std للهدف يدويًا. القرار المؤقت: C عبر clang + lld-link (شجرة البند 18، الفرضية الثانية) — انظر docs/adr/0001-bootstrap.md.
2. مستودع بعيد: رمز GitHub في البيئة غير صالح؛ لا يمكن إنشاء مستودع من هنا. الأثر: النمط durable غير متاح؛ العمل محفوظ محليًا داخل الجلسة فقط. المعالجة: ينشئ المستخدم مستودعًا خاصًا فارغًا ويرسل رابطه، ثم يُربط ويُدفع إليه. (رُفع: المستودع github.com/ccq9/nawah-os؛ انظر «نمط التشغيل».)
3. KVM: غير متاح. الأثر: تشغيل TCG أبطأ؛ لا أثر على صحة الاختبارات.
4. qemu-system-aarch64: غير مثبت. يُثبت عند بدء تجربة النقل المبكرة (M2–M3).

## أوامر التشغيل الفعلية

- التحقق: python3 tools/project.py validate-records
- البناء: python3 tools/project.py build --target pc-qemu
- الإقلاع: python3 tools/project.py boot --target pc-qemu
- الاختبار: python3 tools/project.py test --target pc-qemu --suite M1
- الحالة: python3 tools/project.py status --json

(تُستكمل الأوامر عند تنفيذ كل واجهة؛ لا يُدرج أمر قبل أن يعمل.)

## مختبر التحقق (CI، platform/pc-qemu/target.json)

- QEMU q35، `-cpu qemu64`، `-m 512M`، **`-smp 4`** (منذ WP-20؛ قبله معالج واحد)، OVMF 4M، قرص virtio-blk 64 MiB (صورة FAT32 تُبنى لكل تشغيل بـ`tools/fat32.py`)، `isa-debug-exit` لرموز الخروج.
- (M4) شبكة QEMU user-mode (SLIRP: الضيف 10.0.2.15، البوابة 10.0.2.2، DNS 10.0.2.3) على `virtio-net-pci` حديث في كل تشغيل؛ خوادم صدى UDP/TCP على loopback المضيف (`host_services` في الحالة) تُبلَغ عبر 10.0.2.2 بلا `hostfwd`؛ مقبس مراقب QEMU بـ HMP (`sendkey`) لحالات لوحة المفاتيح، ومنذ WP-38 مقبس QMP بجانبه (`-qmp unix:…-qmp.sock`): أمرا المختبر `key-down`/`key-up` يُرسَلان بـ `input-send-event` على اتصال واحد للتشغيل (مصافحة مرة، ويُعاد الاتصال بعد اتصال فاشل، TST-M5-LAB-TOOL 9 حالات) فيُمسك مفتاح من خطوة إلى خطوة لاحقة (تحرير Enter الفتح بعد علامة الجلسة، M103)؛ وخطوة بـ `since_previous` لا تطابق علامتها إلا فيما طُبع بعد إطلاق الخطوة السابقة؛ وAlt مضغوطًا عبر Tab يُحقن من نواة الاختبار (`net::inject_keyboard`، ADR-0019 §12)؛ القناة التسلسلية الثانية COM2 في كل تشغيل (`-serial null`، أو خادم TCP `127.0.0.1:<port>` لحالات الـ shell يقودها `ConsoleSession`).
- حالة يمكنها طلب عدد معالجات خاص بمفتاح `smp` (مثلًا اختبارات SMP قبل تعميم 4)، ومهلة خاصة بـ `timeout_s`، ومراحل متعددة على الصورة نفسها بـ `phases` (الثبات).

## نمط التشغيل

- development_worker: interactive (الوكيل في هذه الجلسة). لا مشغّل دائم متحقق.
- verification_runner: GitHub Actions على github.com/ccq9/nawah-os (انقطع 2026-10-23 لفوترة الحساب، R-52، وعاد؛ محلول).
  - `.github/workflows/verify.yml`: عند الدفع إلى main وطلبات الدمج ويدويًا؛ مهلة 40 دقيقة؛ يلغي التشغيل الذي يحل محله دفع أحدث؛ ينشر الأدلة على فرع `ci-evidence/<run>`.
  - `.github/workflows/mutants.yml`: يدويًا وأسبوعيًا (الإثنين 03:17 UTC)، لا على الدفع؛ `validate-records --strict` ثم بناء خط الأساس ثم بوابات الطفرات الأربع بالترتيب: M2 (M01–M29)، M3 (M30–M49)، M4 (M50–M81)، M5 (M82 فصاعدًا)؛ مهلة الحالة الواحدة تحت طفرة 300 ث (`MUTANT_CASE_TIMEOUT_S`، كانت 180)، ومهلة المهمة 300 دقيقة؛ تقرير كل بوابة يُنشر وحده على `ci-evidence/mutants-<run>` فبوابة تخطّت لا تُسقط تقارير غيرها (run 42481065666 فقد تقرير M5).
  - الأدلة تُدخَل بـ `python3 tools/project.py import-ci-evidence --run <id>`، وكل التزام سجلات يمر بـ `tools/pre-merge.sh` (`validate-records --strict` بلا أنبوب).
  - آخر تشغيلين للبوابة M5: verify 42508871862 (الرأس a847a799) والطفرات 42512057372 (الرأس 93006ffd).

## الفحص المحلي قبل الدفع (2026-10-18)

- السبب: في يوم واحد فشل 59 تشغيلًا لـ verify (و5 بملفات workflow غير صالحة)، وكل فشل رسالة بريد إلى صاحب الحساب؛ لأن حالات الضيف كانت لا تُبنى إلا على CI.
- الطريقة: `python3 tools/project.py preflight --suite <M?> [--only <ids>]` يبني الصورة كاملة هنا بـ cargo build-std (`RUSTC_BOOTSTRAP=1`، `-Zbuild-std=core,alloc,compiler_builtins`، `compiler-builtins-mem`) من مصدر المكتبة القياسية عند **إيداع المترجم نفسه**: مستنسخ جزئيًا (`library/` فقط) من GitHub عند الوسم `1.97.0` = الإيداع `2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`، وهو `commit-hash` في `rustc -vV`، ويُربط في `<sysroot>/lib/rustlib/src/rust`؛ تبعيات المكتبة من crates.io (مسموح) تُنزَّل مرة. ثم يشغّل الجناح المختار في QEMU المحلي (8.2.2، OVMF 4M) بأدلة في `build/preflight-evidence/` لا تُربط بالسجلات أبدًا. build-std لبناء صورة الضيف وحده: خطوة الاختبار تبني أدوات مضيف (أمثلة `nawah-text` في `tools/text_check.py`) تربط std المضيف، وbuild-std هناك يعطي نسختين من `core` (E0152) — هذا ما أفشل TST-M5-TEXT-GUEST في أول فحص محلي كامل بينما نجح على CI. ولا يُشغَّل فحصان معًا في مجلد العمل نفسه (يتشاركان صورة القرص ونسخة OVMF_VARS).
- القياس الأول: بناء الصورة كاملة 1د49ث؛ حالات M5 الأربع التي غيّرها WP-37 (INPUT-ROUTE، LOGIN-SCREEN، AUTH-INPUT-ISOLATED، LOCK-SURVIVES) 1د50ث، كلها PASS بالمطابقة الحرفية للنصوص المتوقعة ولقطات الشاشة.
- WP-39 (2026-10-18): فحص محلي لخمس حالات (INPUT-ROUTE غير المتأثرة للتأكد، KEYBOARD-NAV وA11Y-TREE المجمَّدتان، وWINDOW-A11Y وARABIC-UI الجديدتان) — كلها PASS. أمسك الفحص المحلي خطأً قبل الدفع: مقياس السمة في وحي ARABIC-UI كُتب `theme=1` بينما الخدمة تطبعه بالأرباع (`theme=4` = 1×)؛ صُحِّح والحالة تمر بالمطابقة الحرفية لنص القارئ العربي ولقطة الشاشة.
- منذ WP-39: `preflight` يبدأ بـ `cargo fmt --all --check` (أول ما تفعله بوابة الهيجين في CI، ويفشل التشغيل كله قبل الأجنحة إن أخفق)، فيُمسَك خطأ التنسيق محليًا في أقل من ثانية قبل البناء.
- القاعدة: لا دفع إلى main قبل نجاح الفحص المحلي للأجنحة المتأثرة؛ دليل الحكم يبقى تشغيل CI وحده (المكتبة الأساسية هناك من rustup لا من build-std). و`verify.yml` يلغي التشغيل الذي يحل محله دفع أحدث (`concurrency`، TST-M0-003).

## خطاف ما قبل الالتزام

`cp tools/hooks/pre-commit .git/hooks/pre-commit` — يرفض أي commit لا تمر سجلاته بـ `validate-records` (0 أخطاء). أُضيف 2026-10-18 بعد أن أخفى أنبوب `| tail` حالة خروج المدقق مرتين.
