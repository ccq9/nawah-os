# سجل إعادة استعمال Sol OS في nawah-os (ADR-0002) — مطابقة 2026-11-09

المراجع: الوكيل المنفّذ (جلسة التنفيذ). الغرض: مطابقة ما قرّره ADR-0002 (2026-10-18) نقله من مشروع المالك السابق Sol OS (S32: `sol-os-phase2.zip`، آخر commit `d54f0a5` بتاريخ 2026-10-07) مع ما في الشجرة فعلًا، وحصر ما بقي من الأرشيف غير مراجَع ولماذا. كل سطر هنا مربوط بملف في الشجرة أو بسجل في `docs/`؛ لا حكم من الذاكرة ولا من أدلة Sol.

**الخلاصة**: كل ما سمّاه ADR-0002 البند 4 موجود في الشجرة وأُعيد اختباره بأدلة nawah، وكل ملف منقول يحمل سطر أصله إلا `tests/mutants.py` الذي كان بلا سطر أصل حتى هذه المطابقة (أُضيف، ويحرسه TST-M0-002 من اليوم). القرارات التصميمية المستعارة (Sol ADR-006/007/008/010) لها نظائرها في ADRs وعقود nawah. الأرشيف نفسه غير قابل للوصول من جلسات السحابة (القسم 4)، فما لم يُسمَّ في ADR-0002 يبقى غير مراجَع إلى أن يتاح (DEC-010).

## 1. الملفات المنقولة (ADR-0002 البند 4)

| مادة Sol OS (d54f0a5) | في nawah-os | سطر الأصل | أُعيد اختباره بـ | المرحلة |
|---|---|---|---|---|
| `gdt.rs` | kernel/src/arch/x86_64/gdt.rs | نعم (مكيَّف للصورة الواحدة UEFI) | TST-M1-BOOT، جناح M2 للاستثناءات (11 حالة) | M2 (WP-07) |
| `idt.rs` | kernel/src/arch/x86_64/idt.rs | نعم | TST-M2-IDT-LAYOUT (يمشي IDT المعالج عبر `sidt` لا متغيرات النواة)، TST-M2-EXC-* | M2 (WP-07) |
| `trap.rs` | kernel/src/arch/x86_64/trap.rs | نعم (المعالج `extern "sysv64"`) | TST-M2-EXC-DE/UD/DB/GP/PF/BP/BP-STATE/DF/NESTED/TRIPLE | M2 (WP-07) |
| `serial.rs` | kernel/src/arch/x86_64/serial.rs | نعم | TST-M1-BOOT/NEG وكل حالة ضيف (العلامات التسلسلية) | M1 (WP-06) |
| `port.rs` | kernel/src/arch/x86_64/port.rs | نعم | كل حالة ضيف | M1 (WP-06) |
| `qemu.rs` | kernel/src/arch/x86_64/qemu.rs | نعم (رموز الخروج أُعيد تعيينها: ADR-0003 البند 7) | كل حالة ضيف (الحكم برمز الخروج) | M1 (WP-06) |
| `arch/x86_64/ktest.rs` | kernel/src/arch/x86_64/ktest.rs | نعم (بيئة UEFI بخريطة متطابقة) | جناح M2 | M2 (WP-07) |
| `src/cell.rs` | kernel/src/cell.rs | نعم | كل حالة ضيف (خلايا الإقلاع الساكنة) | M1 (WP-06) |
| إطار ktest (Sol ADR-010) | kernel/src/ktest.rs | نعم (أصل التصميم Sol OS ADR-010؛ اسم الاختبار عبر fw_cfg لا سطر الأوامر) | كل حالة ضيف من M2 فصاعدًا | M2 (WP-07) |
| `tests/mutants.py` | tests/mutants.py | **كان مفقودًا؛ أُضيف 2026-11-09** | TST-M0-005 (6 حالات)؛ TST-M2/M3/M4/M5-MUTANTS: 29/29، 20/20، 32/32، 45/45 (mutants-42531135332) | M2–M5 |
| `scripts/check-unsafe.sh` وسياسة unsafe (Sol ADR-008) | tools/check-unsafe.sh، tools/unsafe-baseline.txt، `#![deny(unsafe_code)]` في الجذر | نعم (ADR-0002 البند 6، بعد Sol OS ADR-008) | خطوة hygiene في verify.yml (unsafe policy) | M1 (WP-06) |

التواريخ من ADR-0002/0003 (2026-10-18)؛ تاريخ أول ظهور في git (2026-10-23) أثر إعادة بناء التاريخ (docs/history-rebase-map.json) لا تاريخ النقل.

## 2. القرارات التصميمية المستعارة

| قرار Sol | ما أُخذ منه | نظيره في nawah | الدليل |
|---|---|---|---|
| Sol ADR-006 (القدرات: مقبض + حقوق، لا سلطة محيطية) | النموذج لا الشيفرة؛ النواة تبقى معيارية لا microkernel (ADR-0002 البند 3) | ADR-0011، docs/contracts/ipc.md، kernel/src/object/{handle,channel}.rs | TST-M3-IPC-ROUNDTRIP/RIGHTS-DENIED/CLOSED-HANDLE/IPC-OVERSIZE/IPC-NO-LEAK/HANDLE-TABLE/BLOCK-WAKE (WP-16) |
| Sol ADR-007 (التزامن والجدولة) | مرجع لقفل irqsave وسياسة panic ونموذج الجدولة | ADR-0006، ADR-0010، kernel/src/sync.rs، kernel/src/sched/mod.rs | WP-11 (lock_irqsave، panic_code)؛ WP-15 (TST-M3-THREADS-ALTERNATE/PREEMPT/EXIT-CLEANUP/USER-SLEEP) |
| Sol ADR-008 (unsafe بالمترجم) | السياسة كاملة: deny في الجذر، استثناء boot/arch/cell، تعليق SAFETY، خط أساس بعدّاد يُغيَّر بـ ADR | ADR-0002 البند 6، tools/check-unsafe.sh، tools/unsafe-baseline.txt | hygiene في verify.yml |
| Sol ADR-010 (جداول المعالج ونواة الاختبار) | التصميم بعد المراجعة والتكييف: مكدس مملوك، IST، 32 مدخلًا، رموز الخروج | ADR-0003 | جناح M2 |
| الفحص الذاتي للـ IDT عبر `sidt` (docs/PLAN.md:25) | كما هو، مكيَّفًا | kernel/src/arch/x86_64/ktest.rs (`idt_layout_mismatches`) | TST-M2-IDT-LAYOUT |

## 3. ما رُفض أو تجاوزه المشروع

| مادة Sol | القرار | السبب والمرجع |
|---|---|---|
| الإقلاع عبر Limine (ELF، الهدف x86_64-unknown-none) | مرفوض | ADR-0002 البند 2: الصورة الواحدة والمحمّل الخاص جزء من سلسلة الثقة (Secure Boot وA/B في M9)؛ M1 اجتازت بعقد الإقلاع الخاص؛ ما يقدمه Limine نُفِّذ في M2–M3 بأدلة خاصة |
| أدلة Sol (طفرات 48/48، بوابة 30/30) | لا تُحتسب | ADR-0002 البند 4 وS32 (limits): كل ملف منقول يُعاد اختباره هنا |
| تثبيت rust-std الرسمي من جهاز المالك مع التحقق بالبصمة (Sol: evidence/phase-0/2026-10-07-official-std.md) | موثَّق في ADR-0002 (بصمة المكوّن 2c48c8b6…)، وتجاوزه الفحص المحلي بـ build-std من مصدر المكتبة عند إيداع المترجم نفسه | docs/ENVIRONMENT.md «الفحص المحلي قبل الدفع» (2026-10-18)؛ CI يثبّت الهدف بـ rustup |

## 4. ما بقي غير مراجَع، ولماذا

- الأرشيف `sol-os-phase2.zip` (S32) ليس في هذا المستودع، ولا في أي مستودع GitHub يصل إليه حساب المالك (فُحص 2026-11-09)، ولا في حاوية الجلسة (مجلد الرفع فارغ). مجلد العمل على جهاز المالك مُدرج في قائمة Remote Control لكنه غير معروض لجلسات السحابة (not_available).
- لذلك لا يمكن من جلسة سحابية الحكم على ما لم يُسمَّ في ADR-0002: Sol ADR-001..005 و009 (لا يستشهد بها أي سجل في nawah)، وأداة بوابته (30/30)، وطريقة الطفرات الأصلية فيما قد يزيد على `tests/mutants.py` الحالي، وأدلة phase-0 الأخرى.
- تقدير هندسي: Sol توقّف عند مرحلته الثانية (إقلاع، جداول المعالج، استثناءات، نواة اختبار) وnawah تجاوزت بوابة M5؛ فالقيمة المتبقية المتوقعة في الطريقة والتوثيق لا في شيفرة النواة. لا تُعلَّق أي حزمة من M6 على ذلك.
- القرار للمالك: DEC-010 في docs/decisions-pending.json — إتاحة الأرشيف (مستودع GitHub خاص يُضاف إلى الجلسة، أو رفع الملف المضغوط إليها، أو عرض مجلد العمل لجلسات السحابة) ثم حزمة مراجعة صغيرة محددة النطاق؛ أو قفل إعادة الاستعمال على ADR-0002 البند 4 وتعليم S32 مستنفدًا.

## 5. التغييرات المصاحبة لهذه المطابقة (2026-11-09)

- `tests/mutants.py`: سطر أصل Sol OS (d54f0a5) وفق ADR-0002 البند 4.
- `tests/test_m0_records.py` (TST-M0-002): حالة جديدة تحرس سطر الأصل في الأحد عشر ملفًا المنقولة؛ فشلت أولًا على `tests/mutants.py` وحده (`Lists differ: ['tests/mutants.py'] != []`) ثم مرّت بعد الإصلاح (5 حالات OK).
- `tools/project.py` و`docs/tests.json`: وحي TST-M0-002 ومدخلاته تشمل ADR-0002 والملفات المنقولة.
- ADR-0002: الحالة «مقبول ومنفَّذ» مع إحالة إلى هذا السجل؛ `docs/sources.json` S32: إحالة إلى هذا السجل؛ DEC-010 مفتوح.
- حكم CI: verify run 42600548943 على الرأس f91f4428 أخضر (145 تشغيلًا مستوردًا، TST-M0-002 PASS بالحالة الجديدة)؛ `validate-records --strict` بلا أخطاء، والمتقادم الباقي بوابات الطفرات الأربع (stale_policy warn) لأن `tests/mutants.py` و`tools/project.py` من مدخلاتها ولم يتغير فيهما سلوك.
