# عقد نداءات النظام — الإصدار 1.3 (WP-14 v1، WP-15 v1.1، WP-16 v1.2، WP-19 v1.3؛ ADR-0009، ADR-0010، ADR-0011، ADR-0014)

مجمَّد: أي تغيير في الأرقام أو الرموز أو تمرير الوسائط = إصدار جديد مع سجل قرار. الإصدارات 1.1 و1.2 و1.3 **إضافية فقط**: 4–5 (المجدول)، 6–12 (المقابض والقنوات وVMO، تفصيلها في `docs/contracts/ipc.md`)، 13–19 (الملفات، تفصيلها في `docs/contracts/files.md`)؛ كل ما في الإصدار 1 باقٍ بلا تغيير. الكود: `kernel/src/syscall/mod.rs` (المحايد)، `kernel/src/arch/x86_64/syscall.rs` (الدخول/الخروج/النسخ)، `kernel/src/sched/` (exit/yield/sleep/الحجب)، `kernel/src/object/` (الكائنات).

## 1. الاتفاق العام (كل المعماريات)

- رقم النداء عدد 64 بت؛ حتى 6 وسائط 64 بت؛ نتيجة واحدة i64: ≥ 0 نجاح، < 0 رمز خطأ.
- النداء غير المعروف يعيد `ERR_NOSYS`؛ لا panic ولا إنهاء بسبب وسيط سيئ: المؤشرات والأطوال تُفحص وتُرفض بـ `ERR_FAULT`/`ERR_RANGE`/`ERR_INVALID`.
- كل مؤشر مستخدم يجب أن يقع في `[0x80_0000_0000, 0x8000_0000_0000)` وتكون كل صفحة منه حاضرة بعلم المستخدم في فضاء العملية؛ لا نسخة من/إلى ذاكرة النواة أبدًا.
- الاستثناء في حلقة 3 يُنهي **الخيط** بتشخيص `kernel|user_fault|…` ورمز خروج `0x10000 + المتجه`؛ لا يُسقط النواة. آخر خيط يخرج من عملية ينهيها ويصبح رمزه رمز العملية (`wait_process`).

| الرقم | الاسم | الوسائط | النتيجة |
|---|---|---|---|
| 0 | `exit` | code | لا تعود |
| 1 | `ping` | x | x + 1 |
| 2 | `trace` | ptr, len ≤ 256 | len، ويُطبع `user|trace|len=…|text=…` (ASCII؛ غيره `?`) |
| 3 | `check_rip` | addr | 0 إن كان عنوان تعليمات مستخدم صالحًا (canonical وداخل النطاق)، وإلا `ERR_RANGE` |
| 4 | `yield` (v1.1) | — | 0؛ يتنازل عن المعالج لخيط جاهز بأولوية مساوية أو أعلى إن وُجد |
| 5 | `sleep` (v1.1) | ticks | 0؛ يحجب الخيط `ticks` نبضة مؤقت على الأقل (1 kHz؛ الحد الأقصى المقبول 1,000,000 ويُقص إليه) |
| 6 | `channel_create` (v1.2) | out_ptr | 0؛ مقبضان u32 في out_ptr — ipc.md §3 |
| 7 | `channel_write` (v1.2) | h, ptr, len, hptr, nh | 0 — ipc.md §3 |
| 8 | `channel_read` (v1.2) | h, ptr, cap, hptr, hcap, flags | `len \| (nhandles << 16)` — ipc.md §3 |
| 9 | `handle_close` (v1.2) | h | 0 |
| 10 | `handle_duplicate` (v1.2) | h, rights | المقبض الجديد |
| 11 | `vmo_create` (v1.2) | size | المقبض |
| 12 | `handle_rights` (v1.2) | h | حقوق المقبض |
| 13–19 | `open`, `read`, `write`, `stat`, `unlink`, `seek`, `sync` (v1.3) | — | files.md §2 |

رموز الأخطاء: `ERR_NOSYS = -1`، `ERR_INVALID = -2`، `ERR_FAULT = -3`، `ERR_RANGE = -4`؛ (v1.2) `ERR_BAD_HANDLE = -5`، `ERR_ACCESS = -6`، `ERR_PEER_CLOSED = -7`، `ERR_SHOULD_WAIT = -8`، `ERR_BUFFER_TOO_SMALL = -9`، `ERR_NO_RESOURCES = -10`، `ERR_WRONG_TYPE = -11`؛ (v1.3) `ERR_NOT_FOUND = -12`، `ERR_EXISTS = -13`، `ERR_IS_DIR = -14`، `ERR_NOT_DIR = -15`، `ERR_BAD_PATH = -16`، `ERR_NO_SPACE = -17`، `ERR_IO = -18`.

المؤشرات التي تكتب فيها النواة (v1.2) تُفحص لعلم الكتابة أيضًا (`ERR_FAULT` إن كانت الصفحة للقراءة فقط).

## 2. x86_64

- التعليمة `syscall`؛ `rax` = الرقم؛ الوسائط `rdi, rsi, rdx, r10, r8, r9`؛ النتيجة في `rax`؛ `rcx` و`r11` تُستهلكان (RIP/RFLAGS)؛ بقية السجلات محفوظة.
- المقاطع: CS=0x33، SS=0x2B (IA32_STAR[63:48]=0x20)؛ الدخول عبر IA32_LSTAR على مكدس نواة الخيط (يُوجَّه إليه عند كل تبديل، وهو TSS.RSP0 نفسه)؛ IF معطَّل أثناء النداء (IA32_FMASK) فلا استباق داخل نداء؛ `sleep`/`yield` يبدّلان السياق طوعًا من داخل النداء ويعودان بـ IF كما كان.
- العودة بـ `sysretq`؛ لا يُقبل RIP غير canonical أو خارج نطاق المستخدم في أي مسار يبني سياق مستخدم.

## 3. AArch64 (محجوز، يُفعَّل مع الحزمة الثانية من تجربة النقل)

- التعليمة `svc #0`؛ `x8` = الرقم؛ الوسائط `x0..x5`؛ النتيجة في `x0`. الأرقام والرموز ودلالات المؤشرات نفسها.

## 4. الاختبارات الحاكمة

TST-M3-USER-SYSCALL (ping/trace)، TST-M3-USER-BAD-PTR (مؤشر غير مخطط → ERR_FAULT، مؤشر نواة → ERR_RANGE)، TST-M3-USER-KERNEL-ACCESS (قراءة ذاكرة النواة من حلقة 3 → user_fault 14)، TST-M3-SYSRET-CANONICAL (RIP غير canonical يُرفض)، TST-M3-USER-SLEEP (v1.1: sleep(3) ثم yield → خروج 0x51 بعد ≥ 3 نبضات)، TST-M3-EXIT-CLEANUP (الخروج الطبيعي وبالخطأ يحرر كل شيء)، وفحص `kernel|user|…|selfcheck=1` في كل إقلاع.
