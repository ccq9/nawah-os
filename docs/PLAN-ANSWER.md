# إجابة الفريق على الخطة: ما نبنيه أولًا وكيف

> ملاحظة ترقيم (2026-11-09): قرار أرشيف Sol OS كان DEC-010 في هذه الوثيقة وأُعيد ترقيمه إلى DEC-023؛ DEC-010 هو قرار «التحدي العشوائي» في PR #22 (فرع claude/m5-audit-followup). استُبدل المعرّف في النص دون تغيير آخر.

> **بيان الإنتاج والتحقق (المدير التنفيذي: نموذج الجلسة، 2026-11-09).**
> أُنتجت هذه الإجابة بتشغيل `.claude/workflows/nawah-team.js` (التشغيل wf_f3217895-e75) بالأدوار الأربعة عشر التي قررها المالك في DEC-011 على النموذج opus: مخطِّطان، ثلاثة مهندسي برمجيات، ثلاثة مهندسي أنظمة، ثلاثة مهندسي أمن، مدقق، مساعد مدير، مدير دامج؛ 369 استدعاء أداة على المستودع، 66 دقيقة، نحو 3.3 مليون رمز، وكيلان متزامنان بحكم أربعة أنوية. كل وكيل قدّم لكل قرار خيارين أو ثلاثة بمفاضلاتها وأنماط فشلها وقابلية عكسها (قاعدة 5 من تعريفات الوكلاء).
> التدقيق: سجل المدقق الخام 67 حكمًا: 55 مؤكَّد، 8 مردود، 4 غير قابل للتحقق، و19 فجوة (جدول المدير في البند 0 يذكر 63: 52/7/4؛ الفرق أربعة أحكام جمعها المدير). مساعد المدير: 17 تغييرًا في السجلات و17 تناقضًا بين الأدوار حسمها المدير في البند 5.3. المردود مُدرج في البند 5 وأُشير إليه حيث ذُكر خارجه.
> تحقق المدير التنفيذي بعد المدير: 105 معرّف سجل مذكور، 63 موجودة، و42 معلَّمة في النص صراحةً «مقترح» أو NOT_RUN أو «غير موجود» (ومنها WP-64 وWP-65 وWP-66 وDEC-012 إلى DEC-022 وADR-0025 إلى ADR-0028 واختبارات M6/M8/M9/M10 المقترحة). 112 استشهاد ملف:سطر حُلّت إلى ملفات موجودة وأسطر داخل حدودها (98 بالمسار و14 بالسياق إلى sessiond وlibui)، واستشهاد واحد خارج الحدود: `check-unsafe.sh:23` في البند 2.1، والملف 21 سطرًا والمقصود السطران 4 و20 (قاعدة خط الأساس). 8 إحالات إلى سطور البرومبت كلها صالحة.
> توضيح لازم: «الكاتب الآخر» الذي رصده الفريق في الإيداع 5f48703c أثناء التشغيل هو المدير التنفيذي نفسه (استيراد دليل verify 42627452529)؛ لا كاتب ثانٍ للسجلات. الخطوة K0 من البند 1.3 (checkpoint 59 عند 5f48703c) أُنجزت في الإيداع الذي يحمل هذه الوثيقة. نص المدير أدناه لم يُعدَّل.

- **التاريخ:** 2026-11-09
- **الرأس عند الكتابة:** `5f48703c` («Import verify run 42627452529 evidence (head 9ceb133a)»)
- **ما يجيب عنه:** `docs/PLAN-REVERSE.md` (2026-11-09)
- **المنتج المسمى:** `CLAUDE.md:3` و`docs/policies/team-methodology.md:43`. الملف لم يكن موجودًا قبل هذه الإجابة.
- **الحالة:** نص مقترح للإيداع في C1 (القسم 4). كل ما وُصف هنا بأنه «مقترح» غير موجود في السجلات بعد. كل تشغيل محلي مذكور هنا مسودة لا دليل، والحكم لـ CI.

---

## 0. الإجابة في صفحة

**ما نبنيه أولًا:** نمط الإقلاع التفاعلي وبيان النظام. هذا هو الجزء الأول من `WP-45` بعد قسمتها عند النقطة التي يسميها سجلها (`docs/work-items.json` WP-45 actions[5]) والتي يأمر بها `docs/adr/0019-graphics-platform.md:48`. ينص السطر 48 على أن تغيير نمط الإقلاع «يغيّر اختبارات M1 فيُنفَّذ حزمةً مستقلة». أما مراقب الجلسة والشاشات العربية فينتقلان إلى حزمة جديدة هي `WP-64` (مقترحة).

**بأي ترتيب:**

| # | الخطوة | الحَكَم |
|---|---|---|
| K0 | تسمية كاتب سجلات واحد، ثم `checkpoint` رقم 59 عند `5f48703c`. الاستيراد C0 أنجزه كاتب آخر أثناء هذا التشغيل. | `validate-records --strict` بلا أخطاء. المسودة المحلية عند `5f48703c` أعطت 0 أخطاء و17 تحذيرًا. |
| C1 | إيداع سجلات فقط: قسمة WP-45، وإنشاء `WP-64` و`WP-65` بحالة planned، وتصحيح PLAN.md وstages.json وproject-state، وهذه الوثيقة. | `--strict` = 0 في CI |
| WP-65 | حزمة ضمان (مقترحة) في حلقة verify واحدة: فحص الاستيراد، وهوية الدليل 1.1.0، و`dirty_state`، و`stage_of` للمرحلة M6، وحراس المراسي والأجنحة. تُستورد أدلتها بالأداة الجديدة نفسها. | `TST-M0-001`، `TST-M0-003`، `TST-M0-005`، `TST-M0-007` (مقترح) |
| WP-45 | C2 تفعيل، ثم C3 العقود، ثم C4 الاختبارات الفاشلة أولًا، ثم C5 الكود، ثم verify كامل، ثم C6 الإغلاق. | `TST-M6-INTERACTIVE-BOOT`، `TST-M6-MANIFEST-LINT` (مقترح)، `TST-M6-HOLD-FAIL-CLOSED` (مقترح)، `TST-M1-BOOT/NEG/NOBS`، `TST-M0-003`، `TST-M0-005`، `TST-M5-LAB-TOOL` (2026-11-09: انتقل TST-M6-HOLD-FAIL-CLOSED إلى WP-67) |
| بعدها | تصير `WP-46` و`WP-49` و`WP-64` جاهزة. تُفعَّل `WP-64` قبل `WP-49` بسبب ترقيم `ui.md`. | `TST-M6-SESSION-WATCHDOG`، `TST-M6-SESSION-AR`، `TST-M6-SESSION-STRINGS` (مقترح)، وانحدار M5 |
| قبل WP-62 | `WP-66` (مقترحة): فصل وظيفة النشر، وبوابة التقادم، والمقيّم داخل مدخلات أحكام الضيف، وعدّ unsafe الواصل إلى الإصدار، وبوابة طفرات M6. | `TST-M0-003`، `TST-M0-008` (مقترح)، `TST-M6-STALE-GATE` (مقترح) |

الدمج إلى `main` قرار المالك وحده، ويكون تقديمًا سريعًا للإيداع الذي تحقق منه CI. لا ندمج نحن.

**من أنتج الإجابة ومن دقّقها:** الأدوار الأربعة عشر بقرار المالك `DEC-011` (الخيار 2، `docs/decisions-pending.json` DEC-011، answered):

| الدور | ما قدّمه |
|---|---|
| nawah-plan-ladder | سلّم القبول M6→M15، والقرارات DEC-012..021 (مقترحة)، والمخاطر |
| nawah-plan-chain | سلسلة WP-45..WP-63، والقسمة B، وتسلسل التفعيل |
| nawah-sw-kernel | نمط الإقلاع ومفتاح الفحص الذاتي (K1)، والبيانان |
| nawah-sw-services | بيان النظام وسياساته، والمراقب، والتطهير، وconfig، والمؤشر |
| nawah-sw-apps | جداول النصوص، والشارة، وValue بأساس LTR، وقصّ المقياس، والأوراكل |
| nawah-sys-lab | اختيار حالة الإقلاع، وجناح M6، وميزانية verify، والطفرات |
| nawah-sys-platform | system_reset، وrtc_read، وS5، وبوابة المحاكي، والطريق إلى جهاز حقيقي، وDMA |
| nawah-sys-release | أصل الدليل وفحص الاستيراد، وdirty_state، وصورة الإصدار، والعقد |
| nawah-sec-threat | قسم M6 في نموذج التهديد |
| nawah-sec-assurance | إصلاحات الضمان S1 وترتيبها |
| nawah-sec-redteam | الهجمات التي يجب أن تصمد أمامها التصاميم |
| nawah-auditor | 63 حكمًا: 52 مؤكدًا، و7 مردودة، و4 غير قابلة للتحقق |
| nawah-assistant-manager | قائمة تغييرات السجلات، وفحص الميزانية، والفحوص المحلية |
| nawah-manager | هذه الوثيقة، وحسم التناقضات (القسم 5.3) |

ما يلي يأخذ بأحكام المدقق. كل ادعاء مردود أو غير متحقق نُقل إلى القسم 5.

---

## 1. الخطوة الأولى WP-45: القرار

### 1.1 الحالة عند `5f48703c`

- تشغيل verify رقم `42627452529` على `9ceb133a` انتهى بالنجاح: status=completed، conclusion=success، event=pull_request (`gh run view`). الفرع `ci-evidence/42627452529` منشور.
- أنجز كاتب آخر الإيداع C0 أثناء هذا التشغيل، وهو `5f48703c`.
- `validate-records` و`validate-records --strict` عند `5f48703c` يعطيان 0 أخطاء و17 تحذيرًا و16 حكمًا قديمًا (مسودة). الأحكام القديمة الستة عشر كلها أحكام طفرات بسياسة `stale_policy=warn` (`tools/project.py:82-84` و`169-175`). التحذير الوحيد في project-state هو «source_revision ad8d7ada != HEAD 5f48703c (checkpoint pending)».
- `docs/project-state.json`:
  - `source_revision=ad8d7ada`
  - `checkpoint_generation=58`
  - `dirty_state=true`
  - العقد `lease` منتهٍ (acquired_at 2026-10-24T14:30:00Z، ttl_s 900)
  - `pending_decision_ids=[DEC-002]`، مع أن `DEC-023` حالته open
- `WP-45` هي الحزمة الوحيدة الجاهزة بقاعدة الاعتماد: `WP-38` في حالة done (`tools/project.py:332-337`). أما نتيجة CI على `5f48703c` نفسه فلم تُقرأ.

**النتيجة:**
- الشرط المسبق 1 في `PLAN-REVERSE §2` سليم محليًا.
- الشرط 2 مفتوح، لأن checkpoint لم يُكتب. لذلك أول خطوة هي checkpoint، لا الاستيراد.
- ظهور كاتبين والعقد منتهٍ يجعل تسمية كاتب واحد شرطًا يسبق أي إيداع سجلي (القسم 5.3، البند 1).

### 1.2 القرار: القسمة B

**ما يبقى في `WP-45`:**
- نمط الإقلاع.
- بيان النظام `/SYSTEM/SERVICES.TXT`.
- البيان المختبري الفارغ `/SYSTEM/SELFTEST.TXT`.
- `TST-M6-INTERACTIVE-BOOT`، و`TST-M1-BOOT/NEG/NOBS`، و`TST-M0-003`.
- بقرار المدير (القسم 5.3) يُضاف أيضًا: `TST-M6-MANIFEST-LINT`، و`TST-M6-HOLD-FAIL-CLOSED`، و`TST-M5-LAB-TOOL`، و`TST-M0-005`. (2026-11-09: انتقل TST-M6-HOLD-FAIL-CLOSED إلى WP-67).

**الحزمة الجديدة `WP-64` (planned، المرحلة M6):**
- `requirement_ids=[REQ-M6-002]`
- `depends_on=[WP-45]`
- النطاق: المراقب، و`session.md` v1.7، والشاشات العربية، ومؤشر لغة الإدخال.

**الحزمة `WP-47`:** تصبح `depends_on=[WP-46, WP-64]`. لا تتغير `depends_on` في `WP-62`، لأنها تصل إلى `WP-64` بالتعدي. تبقى `REQ-M6-002` مشتركة بين الحزمتين، ولذلك سوابق في السجلات: `REQ-M6-006` بين WP-49 وWP-50، و`REQ-M6-020` بين خمس حزم. تصبح `REQ-M6-002` في حالة `partial` عند إغلاق WP-45، ولا تصبح `verified_in_scope` قبل إغلاق WP-64.

**السبب:**
- الحزمة المسجلة تحمل مسارين في طبقتين.
- الأول نمط الإقلاع. نواة الإصدار تخرج دائمًا بعد الفحص الذاتي (`kernel/src/kmain.rs:569-572`). و`TST-M1-BOOT` هي الحالة الوحيدة من 124 حالة تقلع `NAWAH.EFI`، والبقية: 122 على NAWAH-KTEST، وواحدة على NAWAH-NEG (عدّ `target.json`، مؤكد).
- الثاني تعديل الجلسة على نواة الاختبار.
- `WP-46` و`WP-49` تحتاجان المسار الأول فقط.
- ربط `WP-47` بـ`WP-64` له سبب أمني مؤكد. الجلسة المعادة بعد قتلها تعرض شاشة الدخول دون إرسال LOGOUT إلى display (`user/apps/sessiond/src/main.rs:783-801`؛ LOGOUT يُرسل في 1236 و1242 فقط). وdisplay عند إغلاق قناة الجلسة يحجب الشاشة ولا يزيل النوافذ (`docs/contracts/display.md:42`).
- سلسلة `session.md` تبقى بلا إعادة ترقيم: v1.7 في WP-64، ثم v1.8 في WP-47، ثم v1.9 في WP-51، ثم v1.10 في WP-53.

**البدائل المرفوضة:**
- **A، بلا قسمة:** التقدير يتجاوز الميزانية على الأرجح. نطاق الشاشات وحده يشمل crate جديدًا، وشارة في libui، وValue بأساس LTR، وقصّ المقياس، وجداول عربية، وملف expect مكتوب يدويًا. والسجل نفسه يأمر بالقسمة إن تجاوز التقدير الميزانية (actions[5]؛ prompt:44 و71 و73). هذا التقدير بعدد الملفات، لم يُقس.
- **C، قسمة ثلاثية:** `WP-64` و`WP-65` المقترحتان فيها تعدّلان كلتاهما `user/apps/sessiond/src/main.rs` و`session.md`، فالتوازي اسمي فقط. وتحتاج إعادة ترقيم ثلاث حزم، وثلاث حلقات CI بدل اثنتين، والحلقة تستغرق نحو 30 دقيقة (`42617915972`: 28m55s).
- **B2، WP-64 مستقلة عن WP-47:** تترك تفاعل المراقب مع مهمة الجلسة بلا مالك، وتُحدث إعادة ترقيم.
- **WP-45 superseded:** `tools/project.py:329-330` يرفض التبعية لحزمة superseded، و`WP-46` و`WP-49` تعتمدان على `WP-45`.

**قابلية العكس:**
- قبل تفعيل WP-45 الكلفة منخفضة: تُحذف WP-64 planned ويُعاد نطاقها في إيداع سجلي واحد، بعد إزالة WP-64 من `depends_on` في WP-47 أولًا.
- بعد إغلاق WP-45 يصير العكس مكلفًا. إضافة اختبارات NOT_RUN إلى `test_ids` حزمة done خطأ (`project.py:310-317`)، فيلزم الانتقال done→planned (`project.py:21`).

### 1.3 تسلسل التفعيل

هذا التسلسل هو ما اقترحته خريطة السلسلة، معدّلًا بالتدقيق وبقائمة المساعد. والعناوين تمر بـ`DEC-004`. تفصيل التغييرات في القسم 4.

0. **K0:** تسمية الكاتب الوحيد، ثم `python3 tools/project.py checkpoint` عند `5f48703c`. يصبح `checkpoint_generation=59` و`source_revision=5f48703c`، و`current_task=WP-45` (يشتقها `derive_position`، `project.py:1432-1446`). العنوان «Checkpoint 59 at 5f48703c» لا يسمي حزمة، فيمر.
1. **C1:** «Records: split WP-45 per its budget line and ADR-0019:48; WP-64 and WP-65 planned». سجلات فقط، والعنوان لا يبدأ بـ`WP-45` لأنها planned (`project.py:1478` و`1497-1499`). لا يُعدَّل فيه `docs/PLAN-REVERSE.md` لأنه مدخل لـ`TST-M0-002` (`project.py:1195-1203`).
2. **WP-65:**
   - W0: «WP-65: activate».
   - W1: الاختبارات الفاشلة أولًا، وخرج فشلها المحلي مسودة.
   - W2: الإصلاحات وADR-0026.
   - يُدفع W1 وW2 معًا، ثم verify.
   - W3: «WP-65: close». يُستورد بالأداة الجديدة نفسها، ثم `--strict` = 0، ثم checkpoint.
3. **C2:** «WP-45: activate (boot mode and the system manifest)». تصير الحالة active، ويُضاف سطر تقدير مؤرخ مقابل الميزانية، ثم checkpoint. يظهر التحذير المتوقع «promises services.md v1.11 but the contract is v1.10» (`project.py:300-309`). أما `boot.md` فلا يُفحص لأن رقم إصداره في السطر 3.
4. **C3:** «WP-45: services.md v1.11 and the boot-mode decision in boot.md; PLAN-REVERSE §2 refreshed». العقود قبل الكود. تعديل `boot.md` و`PLAN-REVERSE.md` يُقدِم `TST-M0-002` في الحلقة نفسها.
5. **C4:** «WP-45: failing tests (INTERACTIVE-BOOT, M6 suites, boot-case selection, MANIFEST-LINT, HOLD-FAIL-CLOSED)». لا يُدفع منفردًا (`sys-lab` D4)، ويُعرض فشله من `preflight` مسودة. (2026-11-09: انتقل TST-M6-HOLD-FAIL-CLOSED إلى WP-67).
6. **C5:** «WP-45: interactive boot path; lab self-test behind the fw_cfg key». ثم الفحوص المحلية بالترتيب: `validate-records`، ثم `cargo fmt --all --check`، ثم `hygiene`، ثم `preflight --suite M1`، ثم `preflight --suite M6`. ثم يُدفع C4 وC5 معًا.
7. **[CI]:** verify كامل أخضر لكل أجنحة الضيف، لأن `kernel/src/**/*.rs` و`platform/pc-qemu/manifests/*.txt` مدخلات لكل حكم ضيف (`target.json` build.input_globs، مؤكد). ثم C6: «WP-45: close». الاستيراد مفحوص، ثم done، ثم `REQ-M6-002` partial، ثم `--strict` = 0، ثم checkpoint.
8. الدمج إلى `main` قرار المالك.

---

## 2. التصاميم المختارة

هذا القسم يحمل ما أكده التدقيق فقط. ما ردّه التدقيق موجود في القسم 5.

### 2.1 نمط الإقلاع ومفتاح الفحص الذاتي (WP-45، nawah-sw-kernel وnawah-sys-platform)

**المختار، K1 بحراسة:** تُبنى `fwcfg` في نواة الإصدار، ويُرفع `cfg(feature="ktest")` عن `kernel/src/arch/x86_64/mod.rs:29-30`. ثم يُحسم النمط وقت التشغيل في وحدة آمنة جديدة `kernel/src/bootmode.rs` (الاسم مقترح)، لا في `kmain.rs`. الترتيب:
1. بوابة المحاكي: `CPUID.1:ECX[31]` عبر `__cpuid` الآمن (`mod.rs:72-73`). إن كان البت صفرًا فلا يُلمس أي منفذ، والنمط تفاعلي.
2. توقيع fw_cfg يساوي `QEMU` (`fwcfg.rs:46-52`).
3. ملف باسم مستقل `opt/nawah/selftest` قيمته بالضبط `"1"`.

غياب المفتاح، أو أي قيمة أخرى، أو اسم ktest القائم `opt/nawah/test` (`ktest.rs:52`)، كلها تعني الإقلاع التفاعلي. يطبع النظام سطرًا واحدًا:
`OSX|id|kernel|boot_mode|mode=selftest|interactive|source=fw_cfg|none|key=ok|absent|invalid|hv=0|1`

**المسار التفاعلي:**
- يبقى المؤقت عاملًا، فلا `timer_stop`.
- يبدأ المدير ببيان النظام، ثم `arch::context::idle_wait()` بلا نهاية (`context.rs:135`).
- إن فشل المدير: يُطبع `selfcheck=0`، ثم `arch::halt()` دون كتابة إلى 0xF4.

**المفتاح لا يحمل مسارًا ولا اسم بيان:** يختار بين ثابتين مترجمين تحت `/SYSTEM/`.

**بوابة المحاكي تُقاس أولًا:** حالة ktest تطبع `hv=` على CI. إن ثبت أن TCG مع `cpu=qemu64` (`target.json:684`) لا يضبط البت، فالبديل المسجل هو معرّف OEM في ACPI. يُسجَّل القرار النهائي في `boot.md` (القسم 5.3، البند 5).

**المرفوض:**
- **K2، بناء رابع `NAWAH-SELFTEST.EFI`:** يُخرج حكم `TST-M1-BOOT` من الصورة المشحونة، ويخالف `ADR-0019:48`، ويزيد زمن `TST-M1-BUILD`.
- **K3، المفتاح قبل ExitBootServices:** يضيف أسطر unsafe في `boot/`، فيلزم ADR (`ADR-0002` البند 6؛ `check-unsafe.sh:23`). وملف ESP قد يتسرب إلى صورة موزعة.
- **الأبسط، التوقيع وحده بلا CPUID:** يكتب إلى 0x510 على العتاد الحقيقي قبل فحص التوقيع (`fwcfg.rs:18-22`).

**مؤكد بالتدقيق:**
- سياسة unsafe عدّ نصي لا يعتبر cfg (`tools/check-unsafe.sh:11-13`). سطرا `fwcfg.rs:21` و`26` محسوبان اليوم في الرقم 186 (`tools/unsafe-baseline.txt`)، فالتغيير لا يمس خط الأساس.
- `TST-M1-NOBS` يرفض السلسلة الفرعية `efi` في أي موضع من `kmain.rs` (`tests/test_m1_nobs.py:9` و`16-17`)، ولذلك يُوضع المنطق خارج `kmain.rs`.

**أنماط الفشل:**
- **VM إنتاجية تحت QEMU يُمرَّر لها المفتاح:** تُجري الفحص الذاتي وتخرج. الأثر على التوفر فقط، ومن يملك سطر أوامر المشرف يملك الضيف أصلًا. يُضاف مدخل في `threat-model.md` بجانب السطر 25.
- **بت المشرف غير معروض تحت TCG:** يقلع `TST-M1-BOOT` تفاعليًا ويفشل بالمهلة. الفشل صاخب، لأن المهلة FAIL (`project.py:1169-1170`).
- **مشرف غير QEMU يضيء البت:** تُكتب قيمة إلى 0x510 قبل فحص التوقيع. الأثر غير متحقق، ويُسجَّل حدًّا.
- **dead_code أو clippy في إعداد الإصدار:** `hygiene` يشغّل clippy لكل إعداد (`project.py:1620` و`1656`).
- **اسم المفتاح في `target.json` يخالف ما تقرؤه النواة:** يحرسه اختبار مضيف في `TST-M0-003` (sys-lab D1).

**قابلية العكس:**
- قبل الإغلاق: الكلفة منخفضة. يعود الـcfg، ويُحذف `bootmode`، وتُزال `qemu_extra`، وخط الأساس لا يتغير.
- الانتقال إلى K2 لاحقًا ممكن باستبدال قراءة fw_cfg بـ`cfg!(feature="selftest")` في دالة واحدة.
- بعد الإغلاق: حلقة verify كاملة.

**الملفات:** `kernel/src/kmain.rs` (558-573)، و`kernel/src/bootmode.rs` (جديد)، و`kernel/src/main.rs`، و`kernel/src/arch/x86_64/mod.rs:29-30`، و`kernel/src/arch/x86_64/fwcfg.rs:1` (تعليق «test kernel only»)، و`kernel/src/services.rs`، و`platform/pc-qemu/target.json`، و`docs/contracts/boot.md`، و`docs/security/threat-model.md`، و`docs/tests.json`.

**الاختبارات التي تفشل أولًا:**
- **`TST-M1-BOOT`:** يُضاف `qemu_extra` بقيمة `[-fw_cfg, name=opt/nawah/selftest,string=1]`، ووسم إلزامي `|kernel|boot_mode|mode=selftest|source=fw_cfg|key=ok|`. يفشل عند الرأس، وهو تقوية لا إضعاف. يبقى رمز الخروج 33.
- **`TST-M6-INTERACTIVE-BOOT`:** على `${OUT}/NAWAH.EFI` بلا مفتاح.
  - الإلزامي: `mode=interactive|source=none` و`hv=1`.
  - الممنوع: `|kernel|m1_done|`، و`|ktest|`، و`selfcheck=0`.
  - يفشل اليوم لأن الصورة تطبع m1_done وتخرج بالرمز 33 (`kmain.rs:571-573`).
- **مراحل سلبية داخل INTERACTIVE-BOOT** (لا سجل منفصل):
  - `opt/nawah/selftest=0`، والمتوقع `key=invalid` وإقلاع تفاعلي.
  - `opt/nawah/test=exc_de` على صورة الإصدار، والمتوقع `source=none` وعدم ظهور `|ktest|start|`.
  - قيمة `svc-sh`، والمتوقع ألا يظهر أثر shell على COM2.
  - حالة `-cpu qemu64,-hypervisor` مع المفتاح، والمتوقع إقلاع تفاعلي بلا كتابة إلى 0xF4. هذه محاكاة لغياب المحاكي لا دليل عتاد.
- **`TST-M1-NEG`:** يبقى دون تعديل، لأنه يخرج بالرمز 97 قبل EBS (`boot/stub.rs:38`). و`TST-M1-NOBS` يُعاد تشغيله لتقادم مدخلاته (`project.py:1285`).
- **`tools/check-unsafe.sh`:** يجب أن يطبع `186 (baseline 186)`. هذا في hygiene، والحكم لـCI.

### 2.2 البيان والخدمات (WP-45، nawah-sw-services)

**D1، المختار:**
- يصير `SERVICES.TXT` بيان النظام بخدماته الثماني.
- `SELFTEST.TXT` فارغ إلا من التعليق، ويختاره المفتاح.
- علامة `TST-M1-BOOT` تتغير من `manifest=/SYSTEM/SERVICES.TXT|reply=OK 0` (`target.json:770`) إلى `/SYSTEM/SELFTEST.TXT`، مع بقاء `reply=OK 0` و`code=ok` و`selfcheck=1` ورمز الخروج 33. هذا تغيير مسار معلن لا يُضعف الأوراكل.
- `INTERACTIVE-BOOT` يطلب `manifest=/SYSTEM/SERVICES.TXT|reply=OK 8`. الرد OK 8 صحيح بالشيفرة: `load()` يزيد n بواحد لكل سطر خدمة ويرد `OK <count>` (`user/apps/svcmgr/src/main.rs:269-398`، مؤكد).

**D1، المرفوض:**
- `SYSTEM.TXT` بيانًا للنظام: يلزمه تعديل `REQ-M6-002` وأوراكل INTERACTIVE-BOOT و`session.md:105` وعنوان `services.md §2`.
- ملف واحد بقسمين: يمس محلل svcmgr، ويغيّر معنى OK 0.
- `LABEMPTY.TXT` (القسم 5.3، البند 7).

**D2، محتوى البيان، المختار B.** المسودة، وتُثبَّت قيمها بالقياس:

```
auth     /SYSTEM/AUTHD.ELF     -                                  60000 on-failure 3 100
config   /SYSTEM/CONFIGD.ELF   -                                   5000 on-failure 3 100
net      /SYSTEM/NETD.ELF      -                                   5000 on-failure 3 100
input    /SYSTEM/INPUTD.ELF    -                                   5000 on-failure 3 10 watchdog=2000
display  /SYSTEM/DISPLAYD.ELF  input                               5000 on-failure 3 10 watchdog=2000
narrator /SYSTEM/NARRATOR.ELF  display                             5000 on-failure 3 100
session  /SYSTEM/SESSIOND.ELF  auth,input,display,config,narrator 30000 on-failure 5 100
sh       /SYSTEM/SH.ELF        auth,net                            5000 on-failure 3 100
```

- `watchdog=` للجلسة يُضاف في WP-64 لا في WP-45.
- المراقبة لـinput وdisplay وحدهما، لأنهما وحدهما من خدمات البيان الحقيقي تجيبان PONG (grep `b"PONG"`).
- قيمة 2000 تقدير بين 200 (`svc-lh.txt:7-8`) و8000 (`svc-sg.txt:9`)، لم يُقس.
- مهلة الجلسة 30000 بدل 5000. السبب: قبل READY تحمّل الجلسة خطين، وتجري ثلاثة CONNECT، وطلبات display (`sessiond main.rs:1991-2080`)، وفشل المهلة نهائي (`services.md:64`). وسابقة `svc-sd.txt:8` فيها 120000.

**D2، المرفوض:**
- نسخ بيانات المختبر (never، و5000): أي انهيار يصير نهائيًا.
- watchdog للخدمات الثماني: يحتاج كودًا في خمس خدمات، وخدمة مراقبة لا تجيب تُقتل (`services.md:23`).

**D3، التبعيتان config وnarrator صلبتان الآن، مع خطر مسجل** (RSK-018، مقترح):
- CONNECT مقصور على التبعيات المعلنة (`services.md:69`).
- narrator جاهز قبل أول إعلان (`svc-sa.txt:1-3`).
- displayd لا يعيد الإعلان عند تسجيل القارئ (`displayd main.rs:1730-1741`).
- التبعية اللينة `name?` قرار فريق لاحق.
- **تبعية config تُعلن في البيان، لا في ثابت `DEPS`** في `sessiond:58` (القسم 5.1، البند 7).

**D9:** سطر تصحيح مؤرخ تحت `ADR-0019:48`، ونص السطر اليوم «(auth, config, net, input, display, session, sh)». يحيل التصحيح إلى `services.md` v1.11: ثماني خدمات بإضافة narrator، والسبب أن الجلسة تحتاج سماع الإعلانات الأولى.

**حقائق مؤكدة تمس البيان:**
- المدير يوزع الموارد بالاسم (`svcmgr main.rs:466-491`).
- السطر المسمى `sh` يأخذ المنفذ التسلسلي بكل الحقوق.
- `config` تأخذ `files_write` على كل `/SYSTEM`.

لذلك فالبيان المحمَّل في نمط الإقلاع يقرر سطح COM2 (القسم 3).

**أنماط الفشل:**
- ملء `services.txt` قبل فصل المسار المختبري يكسر `TST-M1-BOOT`.
- اسم أطول من 8.3 يعطي MANIFEST_MISSING.
- البيان بتعليقاته يتجاوز `MANIFEST_MAX=4096` (`svcmgr main.rs:24`). سلوك التجاوز غير متحقق.
- watchdog قصير على display يقتله على عتاد بطيء.
- مهلة auth تنقضي على عتاد بطيء، فتصير session blocked.
- جواب LIST لثماني خدمات قد يتجاوز 1024 بايتًا، وهو مخزن displayd. هذا غير مقيس (القسم 3).

**قابلية العكس:** عالية، لأنها ملفات نصية. كل تغيير يُقدِم أدلة الضيف.

**الملفات:** `platform/pc-qemu/manifests/services.txt`، و`platform/pc-qemu/manifests/selftest.txt` (جديد)، و`kernel/src/services.rs:21` و`150` و`166`، و`platform/pc-qemu/target.json`، و`docs/contracts/services.md`، و`docs/contracts/boot.md`، و`docs/adr/0019-graphics-platform.md`، و`tests/test_m6_manifest.py` (مقترح).

**الاختبارات أولًا:**
- **`TST-M6-MANIFEST-LINT`** (مقترح، host_unit، أول حالة في `HOST_SUITES['M6']`، مالكه WP-45). يتحقق من:
  - قواعد `services.md §2`.
  - ثماني خدمات بأسمائها.
  - أن الحجم أقل من 4096 بايتًا.
  - أن `watchdog` لا يُعطى إلا لخدمة يحوي مصدرها `b"PONG"`.
  - أن كل path موجود في صور البناء.
  - يفشل اليوم لأن `services.txt` بلا خدمات.
  - قيود `W` تضيفها WP-64.
- **`TST-M6-INTERACTIVE-BOOT`** عبر COM2: الأمر `svc` يجب أن يعطي ثماني خدمات ready بقيمة `restarts=0`، مع حارس هامش: `ready_tick-start_tick` للجلسة أقل من نصف مهلتها.

### 2.3 المراقب والتطهير (WP-64، nawah-sw-services وnawah-sec-redteam)

**D4، المختار A:**
- PONG من `on_boot` في الحلقة الرئيسية وحدها، وبعد معالجة دورة كاملة، ويُفحص قبل غيره.
- يكتب `session.md` v1.7 **قاعدة لا رقمًا**: «W أكبر من مجموع مهل النظراء الذين قد تحجب الجلسة عليهم في دورة واحدة».
- القيمة المبدئية 25000 تقدير. المبدأ مؤكد بالتدقيق: `REQUEST_DEADLINE=5000` لكل طلب (`sessiond:50`)، والقتل عند موعد ثانٍ بلا PONG (`svcmgr main.rs:728-750`). أما المعامل فاستنتاج: 4D عند sw-services و3D عند redteam.

**D4، المرفوض:**
- B، أي PONG من داخل الانتظارات المتداخلة: يمس `request` و`elevate_run`، وهما حاكما SESSION-HANG وELEVATE. والأهم أن جلسة عالقة في حلقة داخلية تجيب PONG إلى الأبد، فلا يكشفها المراقب (`services.md:18`).
- C، الإبقاء على الحد: لا يغلق `REQ-M6-002` ولا `RSK-009`.

**D5، المختار B، تطهير عند البدء:**
- الطور الجديد يقرأ LIST على قناة الإقلاع (`services.md:69`).
- إن كان `restarts>0` لسطره، أو فشل التحليل، يرسل LOGOUT إلى display قبل `show(Login)`.
- يضاف إليه، بقرار المدير: **إلغاء رموز auth عند موت العميل**. يحفظ authd فهرس العميل لكل Session، ويستدعي `token_revoke` عند `ERR_PEER_CLOSED`. الآلية مؤكدة بالتدقيق: Session بلا فهرس عميل (`authd main.rs:110-117`)، و`ERR_PEER_CLOSED` يغلق القناة فقط (`697-700`)، و`close_session` تُستدعى في 529 و563 فقط. يُكتب ذلك في `auth.md`.

**D5، المرفوض:**
- A، أي never: كل تعليق يصير توقفًا، ويخالف الأوراكل.
- C، إعادة بلا تطهير: نوافذ المستخدم A تظهر للمستخدم B بعد UNLOCK.

**سياسة given_up:** يكتب `session.md` v1.7 أن given_up الدائم غير مقبول لسطر الجلسة (القسم 5.3، البند 10). والحَكَم فرع «خمس عمليات قتل متتالية، ثم تظهر شاشة الدخول ويعمل الدخول».

**أنماط الفشل:**
- W قصير يقتل جلسة سليمة.
- سيل رسائل يجوّع قناة الإقلاع. أولوية الفهرس في `object_wait_many` غير متحققة.
- تحليل LIST خاطئ يجعل `restarts` يُقرأ 0.
- SAK مستحق عند الموت.
- حالة auth بعد الإعادة: هل يقبل LOGIN جديدًا؟ غير متحقق.
- استنفاد MAX_SESSIONS بتكرار القتل غير مقيس.

**قابلية العكس:** عالية. قيمة في البيان وفرع في `on_boot`.

**الملفات:** `user/apps/sessiond/src/main.rs`، و`user/apps/authd/src/main.rs`، و`platform/pc-qemu/manifests/services.txt`، و`platform/pc-qemu/manifests/svc-sw.txt` (جديد)، و`platform/pc-qemu/expect/session-watchdog.txt` (جديد)، و`kernel/src/ktest.rs`، و`platform/pc-qemu/target.json`، و`docs/contracts/session.md`، و`docs/contracts/auth.md`، و`tests/mutants.py`.

**الاختبارات أولًا: `TST-M6-SESSION-WATCHDOG`** (ضيف على NAWAH-KTEST). يفشل اليوم.
- **المرحلة 1، الانتظار المشروع:** display وinput وauth مجمّدة، مع سيل STATE من spy، ورفع جارٍ مع display وinput معلّقين معًا. بعد `2W+1000` نبضة تبقى الجلسة بقيمة `restarts=0`.
- **المرحلة 2:** تجميد `SESSIOND.ELF`. يقتلها المدير بين `W` و`2W+1000` (`EXIT_KILLED=0x20000`، `restarts=1`).
- **المرحلة 3:** يدخل admin وتفتح spy نافذة، ثم قتل وإعادة. المتوقع:
  - لا بكسل من spy.
  - spy يتلقى LOGGED_OUT.
  - لا تصل المفاتيح إلى spy.
  - يدخل user فيكون `windows=1`.
  - `sak_pending=0`.
- **المرحلة 4:** تجميد الجلسة وسط رفع. الطلب لا يُنفَّذ، والرمز مُلغى.
- **المرحلة 5:** خمس عمليات قتل متتالية، ثم يعمل الدخول.
- **في `TST-M6-MANIFEST-LINT`:** `W_session > 4×REQUEST_DEADLINE`، و`W(services.txt)=W(svc-sw.txt)`.
- **انحدار M5 بآثار مطابقة:** `TST-M5-ELEVATE`، و`LOGIN-SCREEN`، و`LOCK-SURVIVES`، و`LOCK-HANG`، و`SESSION-HANG`، و`SESSION-DEADLINE`، و`AUTH-INPUT-ISOLATED`، و`LOCK-AUTH-HANG`، و`UNLOCK-AUTH-HANG`، و`SVC-WATCHDOG`.

**تحديث 2026-11-09 (قرار المدير بعد تقرير تصميم مهندس الخدمات؛ السجلات حاكمة):**
- قُسمت WP-64. بقي فيها التطهير P-A (`session.md` v1.7). **تصحيح 2026-11-10:** إلغاء الرموز V2 (`auth.md` v1.2) صار WP-73 لخط الميزانية؛ انتقل المراقب W-A وrestart=always (G3) إلى WP-71 والشاشات العربية إلى WP-72، وأرقام إصداراتهما تُعيَّن عند الدمج (PLAN.md:132) لأنهما خارج المسار الحرج.
- إلغاء الرموز عند موت **أي** عميل، كما كُتب في D5 أعلاه، يُبطل رموز sh. لذلك اختير V2: يُلغى فقط ما فتحه العميل `session`.
- التطهير (D5-B) يناقض أوراكل `TST-M5-SESSION-LOSS`، فمراحله اللاحقة تفترض بقاء نافذة spy بعد الإعادة. يُعاد كتابة الأوراكل في WP-64 بعميل يعيد الاتصال، وهذا تغيير يفرضه العقد، لا إضعاف.
- الحَكَم «خمس عمليات قتل» لا يميّز بين on-failure وalways. صار max_restarts+1 قتلًا مباشرًا.
- زمن الحالة نحو 150-180 ثانية، وهو يتجاوز سقف خطوة M6. يُعاد حسم السقف في WP-71.

### 2.4 الشاشات وجداول النصوص (WP-64، nawah-sw-apps)

**T3، الجداول:** crate جديد no_std، اسمه المقترح `user/libsession-text`، في dev-dependencies: libui وnawah-text.
- `enum Lang`، و`enum Msg`، و`fn text(Lang, Msg) -> &'static str`.
- خطط صفوف متطابقة الأدوار والعدد في اللغتين.
- جمل كاملة بلا تركيب ولا إدراج متغيرات.
- رأس مصدر: «صياغة أصلية للفريق، لا ترجمة Windows العربية» (ADR-0022، DEC-009).

المرفوض:
- T1، ثوابت في sessiond: `test = false`، فلا اختبار مضيف (`sessiond/Cargo.toml:8-12`).
- T2، lib+bin: بناء sessiond للمضيف غير متحقق، لأن libnawah فيها `asm!`.

**L2، مصدر اللغة:**
- اتصال config اختياري خارج `DEPS`.
- `GET device` لقيم `ui.lang` و`ui.scale` و`ui.contrast` بمهلة قصيرة قبل أول إطار. عند انقضاء المهلة تُستعمل الافتراضيات مع `session|config=timed_out`.
- ثم `SUBSCRIBE device` على قناة مستقلة.
- قائمة بيضاء: `ui.lang ∈ {en, ar}`، والمقياس بقاعدة `Theme::from_config`.
- **المسار الافتراضي (en، us، 1×) بلا أي سطر تتبع أو إعلان جديد.**

المرفوض: L1، أي config في `DEPS`، لأنها تكسر `ELEVATE config` (`sessiond:58` و`1284`، مؤكد). ولغة المستخدم (L3) حد معلن حتى M7.

**R2، التبديل الحي:** `set_rtl`، ثم relabel، ثم TITLE، ثم repaint، ثم `A11Y <wid> lang`، ثم focus. لا يُعاد البناء. الرسالة تُخزَّن معرّفًا لا نصًا.

المرفوض: `show()`، لأنه يمحو كلمة المرور (`main.rs:965-981`).

**I-3 مع E1، مؤشر لغة الإدخال:**
- شارة في libui لحقلي textfield وpassword: `Dialog::set_badge`، تُرسم في الطرف التالي، ولا تغيّر الوصف ولا الأبعاد.
- مصدر الحدث: STATUS عند العرض، وبعد إفلات Alt أو Shift. قيمة `layout=` في `input.md:50` مؤكدة، وكذلك `input.md:72` «لا حدث».
- ترتيب inputd يضمن أن STATUS بعد الإفلات يرى التخطيط الجديد (`inputd main.rs:376-383`).
- يُصحَّح تعليق `inputd main.rs:377-379` الذي يصف حدثًا غير موجود.

المرفوض:
- I-1، صف Value: يرفع الرفع إلى 12 من 12، ويغيّر `window=` في أوراكل M5. القيمة `window=510,336,260,128` في `expect/login-screen.txt:3` مؤكدة.
- E2، حدث جديد في `input.md`: يصطدم بـv2.7 في WP-51.

**B1، الطلب في RTL، مشروط:**
- يُكتب أولًا اختبار مضيف في libui يقارن الترتيب المرئي للعناقيد بالترتيب المنطقي لقيم مثل `…on/` و`a)` و`9-x`.
- إن ثبتت إعادة الترتيب: يُخطَّط `Role::Value` دائمًا بأساس LTR في الرسم وفي `fits`، ضمن رفع `ui.md` نفسه.
- العزل بـLRI/PDI مردود (القسم 5.1، البند 6).

**S1، قصّ المقياس:**
- إن تجاوز `w×h` قيمة 262,144 (`display.md:35`) نزل المقياس إلى أكبر مقياس يسع، مع `session|scale=clamped|asked=|used=` عند القص فقط.
- إن فشل إنشاء السطح بأي مقياس تُعاد المحاولة بـ1×.
- الأساس مؤكد بالتدقيق: شاشة الرفع بالمقياس 2× مع رسالة أبعادها 520×632 = 328,640 بكسلًا. و`show()` تعود صامتة عند الفشل (`sessiond main.rs:984-986`). وشاشة الرفع فيها 11 عنصرًا من 12، وفشل `add` صامت (`main.rs:868-872`؛ `libui lib.rs:23`).
- يُصحَّح `ui.md:9`.

**n1، الترقيم:** تأخذ WP-64 الإصدار `ui.md` v1.6. وتصبح WP-49 v1.7، وWP-50 v1.8، وWP-63 v1.9 (صُحّح 2026-11-10: WP-49 v1.6، وWP-50 v1.7، وWP-63 v1.8، والشارة لـWP-72 برقم عند الدمج؛ وصُحّح ثانيةً 2026-11-10: ui.md v1.7 لـWP-80 (حوار التأكيد)، وWP-50 v1.8، وWP-63 v1.9). يُسجَّل ذلك في C1، وتُفعَّل WP-64 قبل WP-49. إن فُعّلت WP-49 أولًا يُعاد الترقيم عند الدمج (`PLAN.md:123`).

**O2، الأوراكل:**
- `platform/pc-qemu/expect/session-ar.txt` مكتوب يدويًا ويراجعه دور آخر.
- `forbidden_markers` لكلمة المرور بالنص الصريح وبصيغة `\u{XXXX}`. القارئ يهرّب غير ASCII (`ui.md:20`)، والعلامة الحالية `lab-admin-1` صريحة في 13 حالة M5 (مؤكد).
- فحوص `screen.py desktop --pixel/--ink`.

المرفوض:
- التوليد الآلي من الجداول: تحصيل حاصل.
- `screen.py regions`: أداة جديدة، تؤجل إلى WP-48.

**أنماط الفشل:**
- نص عربي يُقصّ بصمت.
- تجاوز `MAX_ELEMENTS`.
- صياغة منقولة من ترجمة Windows.
- CHANGED أثناء كتابة كلمة المرور.
- قيمة `ui.scale` كبيرة.
- حساب مختبري بكلمة مرور عربية قد لا يقبله authd (غير متحقق).
- بناء crate جديد تحت build-std للمضيف غير متحقق.

**قابلية العكس:**
- الجداول والاتصال الاختياري وقصّ المقياس: عالية.
- واجهة libui الجديدة: متوسطة، لأنها تُجمَّد عند الإغلاق.

**الملفات:** `user/libsession-text/*` (جديد)، و`Cargo.toml` (members)، و`user/apps/sessiond/*`، و`user/libui/src/lib.rs`، و`user/libui/src/tests.rs`، و`user/apps/inputd/src/main.rs` (تعليق فقط)، و`docs/contracts/ui.md`، و`docs/contracts/session.md`، و`tools/project.py` (`HOST_SUITES['M6']`)، و`platform/pc-qemu/expect/session-ar.txt`، و`docs/work-items.json`.

**الاختبارات أولًا:**
- **`TST-M6-SESSION-STRINGS`** (مقترح، host_unit): كل نص يسع صفّه بالمقاييس الثلاثة وباتجاه لغته، والخطط متطابقة، والعدد لا يتجاوز `MAX_ELEMENTS`، ولا تسمية فارغة، وكل شاشة لا تتجاوز 262,144 بكسلًا، وقصّ الرفع من 2× إلى 1.5×.
- **`TST-M5-UI-UNIT`**: حالات `set_badge`، وValue بأساس LTR داخل حوار rtl، و`fits` بالأساس نفسه، وأسوأ حوار بالمقياس 2×.
- **`TST-M6-SESSION-AR`**: الشاشات الثلاث عربية من أول إطار، والتبديل الحي دون محو المكتوب، وAlt+Shift يعطي `layout ar` وحبر الشارة، وصف الطلب `--ink left`، وconfig مجمّدة تبقي الجلسة ready بالافتراضيات وSAK يقفل خلال 500 نبضة، وعلامات التسريب بالصيغتين.

### 2.5 أنابيب جناح M6 (nawah-sys-lab)

**D2-Q2، إنهاء الحالة التفاعلية:**
- خطوة monitor أخيرة `quit`. `run_qemu_monitored` يمرر أي سطر HMP (`project.py:765-781`، مؤكد).
- حقل حالة `ends_by: "monitor"`: لا PASS إلا إن أُرسلت كل الخطوات وكانت الأخيرة `quit`.
- السبب مؤكد: الرمز 0 هو أيضًا رمز إعادة الضبط تحت `-no-reboot` (`project.py:977`؛ `target.json:1057`).
- يُضاف `TST-M5-LAB-TOOL` إلى `test_ids` في WP-45. أوراكله «9 cases» يصير 10.
- رمز خروج QEMU عند `quit` يُقاس محليًا مسودةً قبل كتابة `expected_exit_code`.
- المرفوض: Q1 وحده، لأنه ملتبس. وQ3، الخروج بمفتاح ثانٍ، لأنه يضيف مسار خروج إلى الإصدار.

**D3، جناح المضيف:**
- القاعدة: لا يُضاف جناح قبل أول حالة. جناح فارغ يمر أخضر زائفًا، وجناح مفقود يُرفض (`project.py:1290-1291`، مؤكد).
- أول حالة هي `TST-M6-MANIFEST-LINT` في WP-45 (القسم 5.3، البند 8). فيُنشأ `HOST_SUITES['M6']` وخطوة verify الخاصة به في إيداع C4 نفسه.

**D4-V2، الميزانية:**
- خطوة «M6 guest suite» بعد M5 وقبل A64، بسقف `timeout-minutes: 10`. (مستبدَل: السقف 12 ثم 15 منذ WP-64 في 2026-11-10، و18 لوظيفة M6 في WP-81؛ 2026-11-10: صار ذلك WP-83، وبقي لـWP-81 نصف الأدوات.)
- سقف لخطوة M5 مقداره 18.
- رفع حد الوظيفة إلى 55.
- اختبار يتحقق من أن مجموع السقوف مع هامش 20 لا يتجاوز الحد.
- الأساس مؤكد: 28m55s، منها Toolchain 76 ث وM5 11m34s. الحد 40 (`verify.yml:20`)، وسقف Toolchain 15 (`:37`)، وخطوة M5 بلا سقف. (مستبدَل في 2026-11-10: حد الوظيفة 55 وسقف Toolchain 12، ويعودان إلى 58 و15 في WP-74؛ M5 18 وM6 15.)
- الوظائف المتوازية V3: فُتحت في 2026-11-10 بصفتها WP-74 (نصف الوظائف المتوازية صار WP-81 بقسمة اليوم نفسه، ثم WP-83 بقسمة WP-81 في 2026-11-10، وبقي لـWP-81 نصف الأدوات): مجموع أسوأ حالة لـM6 وحالة مضافة يتجاوز سقفها (WP-71: 755 + 180 > 900)، وخطوة Toolchain قيست ضمن دقيقة من سقفها (11m12s من 12، التشغيل 42754423494)، وM5 أحمر أخفى M6 (التشغيل 42743814734). (الشرط الأصلي: تجاوز زمن M6 المقيس 8 دقائق.)

**D5-P1، حارسان تقاطعيان في `TST-M0-003`:**
- كل جناح ضيف له خطوة verify، في الاتجاهين.
- كل جناح مضيف غير فارغ ومذكور، باستثناء `*-GATE` وM2 صراحةً.
- يمران عند الرأس، فيُكتبان في WP-65. ويفشل الأول عند إضافة `suites['M6']` وحده، فيكون هو الاختبار الفاشل أولًا في C4.

**D6، الطفرات:**
- في WP-65: `stage_of` يعطي M5 للرقم M129 وM6 للرقم M130، و`--stage M6`، وتصحيح الـdocstring. الأساس مؤكد: `tests/mutants.py:595-599` و`761`.
- في WP-66: `HOST_SUITES['M6-GATE']` ووظيفة موازية `mutants-m6` تنشر إلى `ci-evidence/mutants-m6-<run>`. الاستيراد يقبل أي اسم (`project.py:1509`).
  - **تصحيح 2026-11-09 (تدقيق الفريق على 77d48c91):** صار الاستيراد يقبل `<digits>` و`mutants-<digits>` فقط (`RUN_ID_RE`، WP-65)، و`mutants.yml` ينشر إلى `ci-evidence/mutants-<run>`. وظيفة موازية داخل تشغيل mutants نفسه تشترك في `GITHUB_RUN_ID` فلا فرع خاص لها بهذا النظام؛ تختار WP-66 بين تشغيل mutants مستقل لـM6 أو توسيع التعبير والمستورد معًا.
- لا تُضاف `M6-GATE` قبل وجود طفرات M6، لأن بوابة بلا طفرات تحسب على `valid=0`.

**D7-G1، حارس المراسي في `TST-M0-005`:** كل مرساة تتكرر مرة واحدة. شُغّل مسودةً عند `9ceb133a`: 126 مرساة، كلها مرة واحدة. ويُحدَّث `SLOWEST_CLEAN_CASE_S` من 124 إلى 137 (`tests/test_mutants_harness.py:29`؛ `tests/mutants.py:38-45`، مؤكد).

**أنماط الفشل:**
- كشف الإنصاف يوسّع زمن البوابات القديمة (`mutants.py:748-753`). تُراقب المدد.
- هل يبني الكشف `NAWAH.EFI` قبل حالات M6؟ غير متحقق.
- `preflight` يشغّل جناحًا واحدًا (`project.py:1683-1684`)، فيلزم M1 ثم M6.

**الملفات:** `.github/workflows/verify.yml`، و`.github/workflows/mutants.yml`، و`tools/project.py` (`run_qemu_monitored` 734-791، والحكم 1160-1186، و`HOST_SUITES`)، و`tests/test_ci_workflows.py`، و`tests/test_monitor_steps.py`، و`tests/mutants.py`، و`tests/test_mutants_harness.py`، و`platform/pc-qemu/target.json`، و`docs/tests.json`.

### 2.6 اختيار حالة الإقلاع (WP-45 C4، nawah-sys-lab)

**المختار D1-A:**
- تُستخرج دالة نقية `select_boot_case(t)`، ويُحذف شرط `not c.get("qemu_extra")` (`tools/project.py:1053`، مؤكد).
- يحمل `boot_oracle` المفتاح نفسه.
- يُرفض الالتباس إن حمل `test_id` نفسه أكثر من حالة.
- السبب المؤكد: مع المفتاح في حالة الجناح يرجع `project.py boot` إلى `boot_oracle` بلا مفتاح، فيقلع تفاعليًا ويفشل بالمهلة، **فينكسر خط الأساس في `mutants.yml:43-45`**. مسار الطفرات نفسه لا يتأثر، لأن `run_killers` يستعمل `test --suite --only` (`mutants.py:719-733`).
- أصل الشرط الإيداع `7fb68fa4`، وهو أصل الملف، ولا مبرر مكتوب له.

**المرفوض:**
- B: أوراكلان لاختبار واحد، فقد يمر `TST-M1-BOOT` بالأضعف.
- C: `boot` أمر تفاعلي بلا أوراكل، وهذا يوسّع النطاق.

**الاختبارات أولًا (`TST-M0-003`):**
1. حالة الجناح التي تحمل `qemu_extra` هي أوراكل الإقلاع. تفشل بعد استخراج يحفظ السلوك القديم، وتمر بعد الحذف.
2. حالتان بالمعرّف نفسه تعطيان `ValueError`.
3. `qemu_extra` في `boot_oracle` يساوي حالة `TST-M1-BOOT` في `target.json` الحقيقي.
4. اسم المفتاح يظهر نصًا في `kernel/src`.

يتغير «16 cases» في `tests.json` وفي `project.py:1205`.

**قابلية العكس:** بإيداع واحد قبل الإغلاق.

### 2.7 بنود المنصة (nawah-sys-platform)

**system_reset في WP-51 (`syscall.md` v1.14)، المختار A:**
- FADT `RESET_REG` وحده، والإخفاق مغلق بالرمز `ERR_UNSUPPORTED`.
- يُقبل `space_id` 0 أو 1 بعرض 8 بتات، مع فحص `Length` قبل كل حقل.
- `parse_fadt` جديد بإعادة استعمال `find_table` لتوقيع FACP. لا محلل FADT اليوم (`acpi.rs:226` و`316`، مؤكد).
- الترتيب: فحص رمز المدير، ثم إيقاف المدير المنظم، ثم sync، ثم خط الأثر، ثم الكتابة، ثم hlt.
- يشترط الأوراكل خط `via=fadt` وغياب أي خط exception، لأن إعادة الضبط والخطأ الثلاثي كلاهما يخرج بالرمز 0 (مؤكد).

المرفوض:
- B، سلسلة احتياط: تحوّل الفشل إلى PASS تحت `-no-reboot`.
- C، UEFI ResetSystem: `boot.md:17` يمنع استعمال Runtime Services، و`TST-M1-NOBS` يمنعه كذلك.

**محجوب:** لا يدخل العقد قبل قراءة حرفية لـACPI 6.5 §5.2.9 تُسجَّل في `S33`، وقبل تسجيل مصدر QEMU في `sources.json` (القسم 5.2).

**rtc_read، المختار A في WP-51:**
- CMOS عبر 0x70/0x71، مع UIP، والقراءة المزدوجة، وBCD، ونمط 12 ساعة، وCENTURY من FADT، و`IAPC_BOOT_ARCH` bit 5.
- **يُضاف حَكَم مفقود `TST-M6-RTC-READ`** إلى `REQ-M6-007` وWP-51. المتطلب يعد بساعة الشريط من RTC ولا اختبار يحكم عليها (مؤكد).
- الخيار B، نقل rtc_read إلى حزمة نواة، يُعتمد فقط إن تحقق المدقق أن mtime هو السبب الوحيد لاعتماد WP-52 على WP-51. هذا غير متحقق.

**ACPI S5، المختار A:** يبقى مؤجلًا باستثناء بصيغة 22.1. التعويض والمدة يقررهما المالك (القسم 6). المرحلة المستهدفة M8، ويُختار بين AML وResetSystem بعد القياس.

المرفوض: ماسح `\_S5` الأدنى، لأن المختبر لا يميز قيمة مقروءة من قيمة 0 ثابتة.

**حراسة 0xF4:** خارج WP-45، بند قبل Beta (القسم 5.3، البند 6). في WP-45 تحرس البوابة قراءة fw_cfg وحدها.

**الطريق إلى جهاز حقيقي، المختار B، ومرهون بالمالك:**
- مسبار UEFI قبل EBS للقراءة فقط، يكتب على وسيط USB وحده.
- مخطط `hardware` 1.1.0 بحقول kind وfirmware وmeasured_inventory_ref وauthorization_ref وwrite_authorized وdma_isolation وdrivers_required، مع قاعدة مدقق.
- سجل `HW-PC-REAL-01`.
- الفجوة المؤكدة: النواة لا تملك إلا `virtio_blk` و`virtio_net` و`i8042`، فلا AHCI ولا NVMe ولا xHCI.

**DMA للسيناريو 12، المختار B لـBeta:**
- قائمة سماح وBME=0 لأي جهاز PCI غير مدرج.
- اكتشاف DMAR/IVRS دليل لا ادعاء عزل.
- عزل VT-d قرار ADR في M9 أو M10.

**الاختبارات أولًا:**
- حالة وحدة مضيف لمحلل FADT: جدول كامل، وقصير، و`RESET_REG_SUP=0`، و`space_id=2`.
- `TST-M6-RTC-READ`: `-rtc base=2026-11-09T12:34:56,clock=vm`، وحالة `IAPC_BOOT_ARCH` bit5=1 تعطي `ERR_UNSUPPORTED`.
- حالة مضيف لفك حقول RTC.
- `TST-M6-RESTART-PERSIST` بمرحلتين مع `via=fadt`.
- حالات في `TST-M0-001`: سجل physical بلا `authorization_ref`، ودليل pc-qemu في سجل physical، واستثناء بلا تعويض.
- مقترحة بحكم NOT_RUN: `TST-M8-HW-PROBE`، و`TST-M8-SCENARIO-12`، و`TST-M8-S5-MEASURE`، و`TST-M8-SHUTDOWN`، و`TST-M8-REAL-DEVICE`.

**الملفات:** `kernel/src/arch/x86_64/acpi.rs`، و`kernel/src/arch/x86_64/rtc.rs` (جديد)، و`kernel/src/syscall/`، و`kernel/src/arch/x86_64/pci.rs`، و`docs/contracts/syscall.md`، و`docs/schemas/hardware.schema.json`، و`docs/hardware.json`، و`docs/sources.json`، و`docs/decisions-pending.json` (DEC-007)، و`boot/` (المسبار).

### 2.8 أصل الدليل وفحص الاستيراد (WP-65، nawah-sys-release وnawah-sec-assurance)

الأساس المؤكد بالتدقيق:
- أدلة PASS الـ149 كلها `worker=interactive-agent` و`dirty_state=true`.
- منها 145 بقيمة `source_revision=61e65bf1`، وهو التزام غير موجود (`git cat-file`). و4 بقيمة `2cbdeaad`.
- `write_run` لا يُمرَّر إليها worker (`project.py:854`؛ والمستدعيات 924 و1127 و1311).
- `dirty` يُحسب من `git status --porcelain` (`73-76`)، و`evidence/` غير مستثنى في `.gitignore`.
- الاستيراد بلا فحص نتيجة (`1504-1541`)، ويعدّل `notes` (`1531`).
- النشر بشرط `if: always()` ويدفع بـ`-f` (`verify.yml:147-162`).
- **قيس فعلًا** أن لتشغيلين ملغيين، `42623295604` و`42623032466`، فرعَي أدلة منشورين.

**REL-1، المختار C:**
- `evidence-run` 1.1.0 بكائن `ci` يكتبه المشغّل: run_id، وrun_attempt، وworkflow، وevent، وsha، وhead_sha، وref.
- `worker` من تعداد مغلق `[verification-runner, interactive-agent, test]`، يطابق `docs/automation.json:4-18`.
- ملف جانبي `evidence/<rid>/import.json` يكتبه الاستيراد وحده: ci_run_id، وconclusion من API، وhead_sha، وevent، وrun_attempt، وevidence_branch_commit، وimported_at.
- **لا يُمس `run.json`**، فيُحذف تعديل `notes`.
- قاعدة مدقق: الدليل 1.0.0 تحذير، والدليل 1.1.0 المرتبط بـPASS بلا `import.json`، أو بمعرّف مختلف، خطأ تحت `--strict`.
- يُرفع pattern الإصدار إلى `^1\.(0|1)\.0$` مع if/then.
- **تصحيح 2026-11-09 (تدقيق الفريق على 77d48c91):** نُفذت القاعدة أولًا مربوطة بـ`worker=verification-runner` فكانت ادعاءً ذاتيًا (B المرفوض)، وصُححت لتربط كل حكم PASS بإصدار 1.1.0؛ وif/then أُضيفت في التصحيح نفسه (`ci` مطلوب للمشغّل وممنوع في 1.0.0)؛ ولإيصال الاستيراد مخطط خاص `evidence-import.schema.json` مع مطابقة المعرّف والمحاولة والرأس وسير العمل.

المرفوض:
- A، worker من البيئة فقط: نص حر يُزوَّر.
- B: ادعاء ذاتي.
- كتابة قيم API فوق `run.json` (القسم 5.3، البند 11).

**REL-2، المختار A مع فحوص secAssurance:**
- `gh run view <id> --json status,conclusion,headSha,event,workflowName,attempt`.
- يُرفض كل ما ليس completed/success، ومنه cancelled.
- يُرفض workflow غير verify أو mutants.
- يُرفض `headSha` إن لم يكن سلفًا لـHEAD أو مساويًا له.
- يُرفض `run_id` إن لم يطابق `^(mutants-)?[0-9]+$`.
- غياب gh أو خطأه يعطي `E_BLOCKED` بلا نسخ.
- لا خيار `--accept-failed`.
- مقارنة ملف سير العمل بايتيًا، وبصمة سجل التشغيل (secAssurance (ج))، مؤجلتان.

**REL-3، المختار B:** `dirty` على الملفات المتتبَّعة باستثناء `evidence/` و`build/` و`state/`، مع `dirty_paths` لأول 50 مسارًا. لا يُستعمل حَكَمًا قبل قياس أول تشغيل CI.

**REL-5، المختار A مع تسمية كاتب واحد:** `lease=null` مع سبب في `unknown_fields`، وتصحيح `lease_policy` في `automation.json`. تنفيذ prompt:79 يُسجَّل متطلبًا مؤجلًا شرطه أن يسبق أي كاتب ثانٍ. المرفوض B، لأنه يوهم بحماية.

**أنماط الفشل:**
- انتحال `GITHUB_ACTIONS=true`. الحَكَم `import.json` المبني على API، و`SCRATCH` يمنع الإرفاق (`project.py:1373`).
- `pull_request`: `sha` هو التزام الدمج. قاعدة السلف تستعمل `headSha`، وقيمته في `42617915972` هي `14d28100` (مؤكد).
- `run_attempt>1` يستبدل الفرع، فيُسجَّل commit الفرع.
- جلسة بلا gh مصادق تعطي `E_BLOCKED`، والإجراء في القسم 6.

**قابلية العكس:** عالية. 1.0.0 يبقى مقبولًا، والقاعدة تُخفَّف بسطر.

**الملفات:** `docs/schemas/evidence-run.schema.json`، و`tools/project.py`، و`tests/test_validate_records.py`، و`tests/test_ci_workflows.py`، و`docs/automation.json`، و`docs/project-state.json`، و`docs/requirements.json` (`REQ-M0-006`)، و`docs/tests.json` (`TST-M0-007`)، و`docs/adr/0026-evidence-provenance.md` (مقترح).

**الاختبارات أولًا:**
- run.json 1.1.0 فيه `ci` يرفضه المخطط اليوم.
- PASS لحزمة done بدليل 1.1.0 بلا `import.json` يعطي خطأ.
- `import.ci_run_id` يخالف `run.ci.run_id` يعطي خطأ.
- 1.0.0 بلا `import.json` يعطي تحذيرًا. هذا حارس للأحكام الـ149.
- `write_run` تحت `GITHUB_ACTIONS=true` يعطي `worker=verification-runner`.
- `source_identity` مع `evidence/` غير متتبَّع يعطي False. ومع ملف متتبَّع معدّل أو `.rs` جديد يعطي True مع `dirty_paths`.
- gh مزيف يعيد failure أو cancelled أو workflow آخر أو `headSha` غير سلف أو run_id مشوّهًا، فيُرفض الاستيراد ولا يُنشأ مجلد.
- PATH بلا gh يعطي `E_BLOCKED`.
- بعد النجاح يبقى `run.json` مطابقًا بايتيًا، ويوجد `import.json`.

### 2.9 صورة الإصدار (nawah-sys-release)

**REL-4، المختار B:**
- ملفا تعريف للصورة، `lab|release`، يُسجَّلان الآن REQ (M9، deferred) و`TST-M9-RELEASE-NO-LAB-USERS` (NOT_RUN، أوراكل planned)، مع فقرة في `threat-model`.
- حد معلن في `boot.md` وفي قبول WP-45: «الإقلاع التفاعلي على قرص مختبر بحسابات معروفة؛ غير صالح لعتاد حقيقي ولا صورة إصدار».
- الحارس الآلي يُكتب فاشلًا أولًا في الحزمة التي تنشئ أول هدف release. يمنع `lab.users` في هدف release، ويمنع وجود `USERS.DB` و`nawah-lab-salt` و`lab-admin-1` و`lab-user-1` في صورته.
- الأساس مؤكد: `prepare_disk` تبني قرصًا واحدًا لكل هدف، فيه `USERS.DB` بحساب admin/lab-admin-1 (perms=15) وملح ثابت، وكل ELF، وكل بيان ومنها `SVC-SH.TXT` (`project.py:980-1031`).

المرفوض:
- A، توثيق بلا حارس.
- C، ملح عشوائي في المختبر: يكسر قابلية الإعادة بلا كسب.

**REL-6، المختار B، سجلات قبل الأدوات:**
- REQ-M10 لـ22.4 مقسومًا إلى manifest، وSBOM، وتراخيص، وبصمات، وتوقيع.
- `TST-M10-IMAGE-IDENTITY` (NOT_RUN). يشترط أوراكله أن يشمل الجرد مكونات build-std (`core`، و`alloc`، و`compiler_builtins`؛ `project.py:1555-1559`) وNoto/OFL (`sources.json:965-970`).
- ADR الصيغة (`ADR-0028`، مقترح) لا يُكتب قبل تسجيل مصدر الصيغة في `sources.json`.
- التوقيع محجوب على قرار المفاتيح، وترخيص المشروع محجوب على المالك (القسم 6).

### 2.10 قسمة WP-46 (تحديث 2026-11-09، قرار المدير بعد تقرير تصميم مهندس النواة)

- **WP-46 (46a1):** Object::Job (رمز النوع 13)، وjob_create (43)، وjob_kill (44)، وprocess_spawn_in (45)، في `syscall.md` v1.13 و`ipc.md`. التصميم J1: مؤشرات أب صاعدة فقط، والعضوية تُقرأ تحت قفل SCHED، والقتل يمر بمسار القتل القائم داخل القفل. الحاكم `TST-M6-JOB-KILL`.
- **WP-69 (46a2):** process_list (46) بنطاق المقبض. محجوبة بـDEC-027 (ظهور العمليات بين المستخدمين، التوصية A).
- **WP-70 (46b):** المحاسبة، وsystem_info v2، و`ps`.
- **ما نُسخ:** «16 حالة» وترقيم النداءات الواردان في تقرير التصميم تحل محلهما هذه السجلات (`docs/work-items.json`: WP-46 وWP-69 وWP-70؛ `docs/tests.json`: TST-M6-JOB-KILL وTST-M6-PROC-LIST-REFUSALS).
- **الغرفة النظيفة:** مفهوم المهمة يتبع الدلالات المنشورة لمجموعات العمليات في POSIX ولكائن job في Zircon، لا واجهة Job Object في Windows ولا أسماءها. مصدرا المفهومين سُجّلا في 2026-11-09 في `docs/sources.json`: S78 (مجموعات العمليات في POSIX) وS79 (مهام Zircon)، بجانب S39 للمقابض، وتُحقِّق منهما المدير في 2026-11-10 بقراءة صفحاتهما بعد فتح المضيفَين في بيئة الجلسة (sources.json: verified).

---

## 3. الأمن

### 3.1 نص قسم M6 في نموذج التهديد

يُلحق بـ`docs/security/threat-model.md` في C3. صُحّح نصه بأحكام التدقيق: أُزيلت توصية إضافة config إلى `DEPS`، وأُزيل علاج LRI/PDI، ووُحّدت أرقام الطفرات.

> **M6: سطح المكتب والأدوات (WP-45..WP-64؛ يُكتب قبل تفعيل WP-47)**
>
> القاعدة: الواجهة ليست حدًا أمنيًا (ADR-0016 §3؛ stages.json:298). لكل بند طبقة ترفض: النواة، أو المدير، أو الخدمة المالكة.
>
> **1. نمط الإقلاع وبيان النظام (WP-45).**
>
> *الأصول:*
> - سلامة `/SYSTEM/SERVICES.TXT`. بعد WP-45 يصير جذر السلطة في المنتج: المدير يوزّع الموارد المميزة باسم الخدمة (`svcmgr main.rs:466-491`)، والتبعيات المسموحة من البيان (`:613`).
> - اتجاه الإقلاع.
> - حالة الشاشة قبل الدخول.
>
> *الخصوم:*
> - المضيف المختبري، وهو موثوق في المختبر (السطر 25).
> - خدمة config مخترقة، تحمل SystemFiles بحق WRITE على كل `/SYSTEM` (ADR-0020 §2).
> - وصول فيزيائي إلى COM2 على عتاد حقيقي (السطر 42).
>
> *حدود الثقة:* المضيف↔النواة عبر fw_cfg، والقرص↔المدير، والمدير↔الخدمات.
>
> *التحكم القائم:*
> - SystemFiles لـauth وconfig وحدهما.
> - CONNECT مقصور على التبعيات المعلنة.
> - الـcompositor يبدأ محجوبًا إذا ظهرت خدمة session في LIST (`displayd main.rs:1977-1986`)، ويحجب عند فقد الجلسة (`:1099`).
> - fwcfg تفحص التوقيع.
>
> *الفجوات:*
> - (أ) **الحجب عند البدء يفشل مفتوحًا.** `session_in_manifest` تعيد false عند أي خطأ في LIST، ومخزن الجواب 1024 بايتًا. العلاج: الخطأ يعني الحجب.
> - (ب) **config تكتب SERVICES.TXT وAUTHD.ELF وUSERS.DB.** بعد WP-45 يصير اختراقها ثباتًا عبر الإقلاع. العلاج: تعديل ADR-0020 بمقدرة مقيدة بشجرة `/SYSTEM/CFG*`، أو إعلان الحد هنا.
> - (ج) **مفتاح fw_cfg** يختار بين ثابتين مترجمين، ولا يحمل مسارًا، والقيمة المجهولة تعني إقلاعًا تفاعليًا، ولا يمنح امتيازًا. وتسبق القراءةَ بوابةُ `CPUID.1:ECX[31]`.
> - (د) **sh على COM2 داخل بيان المنتج.** على العتاد الحقيقي هو shell بلا جلسة، و`/USERS` و`/APPS` مفتوحة (`vfs.rs:97-114`). مقبول على pc-qemu، ويُحسم قبل Beta.
> - (هـ) **قرص pc-qemu قرص مختبر** بحسابات معروفة وملح ثابت. ليس صورة إصدار.
>
> **2. مراقبة الجلسة (WP-64).**
>
> *الأصول:* توفر القفل، ورمز المدير أثناء الرفع، وعزل جلسة المستخدم السابق.
>
> *الخصوم:*
> - تطبيق يجمّد الجلسة.
> - مكوّن معلّق.
> - مراقب قصير الفترة يقتل جلسة سليمة.
>
> *الفجوات:*
> - الجلسة لا تجيب PING (`session.md:98`).
> - القتل وسط رفع يترك نسخة رمز ADMIN صالحة، لأن authd لا يلغي الرموز عند موت العميل.
> - الجلسة المعادة لا ترسل LOGOUT.
> - given_up يحجب الدخول.
>
> *العلاج:* PONG من الحلقة الرئيسية وحدها، والتطهير عند البدء، والإلغاء عند `PEER_CLOSED`، وW بقاعدة. وتعتمد WP-47 على WP-64.
>
> **3. شاشات الجلسة (WP-64).**
>
> *الأصول:* كلمة المرور، ومطابقة نص الرفع المعروض لما يُنفَّذ، وثبات القفل.
>
> *الخصوم:* كاتب `ui.*`، وconfig معلّقة، وخدمة تصوغ طلب رفع.
>
> *الفجوات:*
> - سطر الطلب داخل فقرة RTL قد يُعاد ترتيبه بصريًا (UAX #9، غير مقيس). العلاج: Value بأساس LTR في libui إن ثبت بالاختبار.
> - config اتصال اختياري خارج `DEPS`، وكل طلب إليها تحت مهلة ولا يؤخر القفل.
> - مؤشر لغة الإدخال إرشادي بلا سلطة.
>
> **4. سمسار التشغيل (WP-47).**
> - `/APPS` قابل للكتابة لكل عملية حتى ADR-0023.
> - التبعيات تأتي من سجل غير موثوق، فيلزم قائمة بيضاء في المدير تستبعد auth وsessiond.
> - البادئة `app:` إلزامية في التزكية، والمحلل يرفض المعرّفات المحجوزة.
> - حد لمعدل LAUNCH.
>
> **5. دور الصدفة (WP-48).**
> - «الصدفة مخفية أثناء القفل» تُفرض في الـcompositor: بالطبقات وبمنع أحداث النوافذ عن الصدفة ما دامت الشاشة محجوبة.
> - ACTIVATE وMINIMIZE وRESTORE وCLOSE_REQUEST للصدفة المزكّاة وحدها، ولا تمس نوافذ الجلسة.
> - SHELL_RESERVE لا يقتطع من احتياط الجلسة.
>
> **6. بقية M6:**
> - **WP-46:** ظهور عمليات المستخدمين الآخرين يُقرَّر قبل ABI.
> - **WP-51:** `system_reset` بلا رمز يُرفض في النواة.
> - **WP-52:** بعد UTF-8 يُتخذ قرار السلطة على المجلد المحلول لا على النص.
> - **WP-53:** المنزل مقدرة مجلد.
> - **WP-54:** منح لحظي من الـcompositor.
> - **WP-57:** اسم المرسل من المدير، ولا نص أثناء القفل.
> - **WP-58 وWP-59:** الرفض في المدير.
> - **WP-60:** قراءة فقط.
> - **WP-61:** يُعدَّل ADR-0020 قبلها.
> - **WP-62:** نطاق M6 في `stage_of` وفي SECURITY، و`m6-review.md`.
>
> **7. حدود معلنة تُراجع عند WP-62:**
> - الجلسة بلا مراقبة بين إغلاق WP-45 وإغلاق WP-64، و`REQ-M6-002` في حالة partial.
> - sh على COM2.
> - جهاز DMA عدائي خارج R1 (السطر 40).
> - قرص المختبر بحسابات معروفة.
> - الحجب عند البدء يفشل مفتوحًا حتى يُصلح 1(أ).

### 3.2 اختبارات طبقة السلطة

| الطبقة | الاختبار | الحزمة |
|---|---|---|
| الـcompositor | فرع `held=1` من STATUS قبل الدخول في `TST-M6-INTERACTIVE-BOOT`، و`TST-M6-HOLD-FAIL-CLOSED` (مقترح، ktest): LIST أطول من 1024 بايتًا أو قناة مغلقة، والمتوقع بدء محجوب | WP-45 (2026-11-09: انتقل TST-M6-HOLD-FAIL-CLOSED إلى WP-67) |
| النواة (`fs_authority`) | config تفتح `/SYSTEM/SERVICES.TXT` و`/SYSTEM/USERS.DB` للكتابة فتلقى `ERR_ACCESS`، بعد تعديل ADR-0020 | مع تعديل ADR-0020 |
| المدير | LOAD خارج `/SYSTEM` يلقى ERR ACCESS (ktest)، وسلسلتا البيان في الكود تبدآن بـ`/SYSTEM/` (فحص ثابت) | WP-45 |
| authd | ELEVATE إلى خدمة تمسك النسخة، ثم قتل الجلسة، ثم WHOAMI بالنسخة يلقى ERR ACCESS، ثم LOGIN بعد عشر عمليات قتل | WP-73 (عدّ الرموز الحية) ثم WP-71 (WHOAMI بالنسخة؛ صُحّح 2026-11-10) |
| sessiond | مراحل `TST-M6-SESSION-WATCHDOG` (القسم 2.3)، وكلمة PONG في دالة الحلقة الرئيسية وحدها (فحص ثابت) | WP-71 (صُحّح 2026-11-10) |
| المدير | فروع `TST-M6-LAUNCH-DENIED`: id=session/desktop/narrator، وdep=auth، والكتابة إلى `/SYSTEM/APPS` | WP-47 |
| الـcompositor | فرع `TST-M6-SHELL-AUTHORITY`: لا حدث إلى الصدفة أثناء الحجب، وACTIVATE على نافذة الجلسة يلقى ERR ACCESS | WP-48 |
| النواة | `TST-M6-POWER-DENIED` | WP-51 |
| النواة | `TST-M5-FILE-AUTHORITY` في `test_ids` لـWP-52، و`TST-M6-RENAME-AUTHORITY` (مقترح) في الاتجاهين، ومقارنة تفاضلية بين classify والحل في `TST-M6-FAT-FUZZ` | WP-52 |
| المدير والنواة | `END-TASK-DENIED`، و`SVC-TOOL-DENIED`، و`PROC-LIST-REFUSALS` بعميل خام (spy) لا عبر الواجهة | WP-46/58/59 |

### 3.3 طفرات SECURITY: التوزيع الموحّد (مقترح)

يحسم هذا الجدول تصادم M130 بين ثلاثة أدوار. آخر معرّف قائم هو M129 (`tests/mutants.py:607-609`). أرقام M146 وM147 في `PLAN-REVERSE.md:226` لا تتسق مع التسلسل. شرط كل الطفرات أن يوجد `stage_of` لـM6 أولًا (WP-65).

| المعرّف | SECURITY | الخلل المزروع | القاتل | الحزمة |
|---|---|---|---|---|
| M130 | نعم | قيمة مفتاح غائبة أو مجهولة تختار الفحص الذاتي | المراحل السلبية في INTERACTIVE-BOOT | WP-45 |
| M131 | نعم | حذف بوابة بت المشرف | حالة `-cpu qemu64,-hypervisor` | WP-45 |
| M132 | نعم | عودة `session_in_manifest` إلى الفشل المفتوح | `TST-M6-HOLD-FAIL-CLOSED` | WP-45 (2026-11-09: الطفرة انتقلت إلى WP-67؛ M130-M132 مسجلة في tests/mutants.py لنمط الإقلاع، وM132 فيها «الإقلاع التفاعلي لا يأخذ خروج الفحص الذاتي»، فتأخذ طفرة الحجز المعرّف الحر التالي في tests/mutants.py عند الدمج؛ M133-M137 في هذا الجدول مخططة لـWP-64، فالحر التالي تخطيطًا M147) |
| M133 | نعم | حذف PONG أو نقله إلى `request()` | فرع التجميد في SESSION-WATCHDOG | WP-71 |
| M134 | لا | W ≤ مجموع المهل | `TST-M6-MANIFEST-LINT` | WP-71 |
| M135 | نعم | تخطي التطهير عند البدء | `TST-M5-SESSION-LOSS` المرحلة 2 (صُحّح 2026-11-10) | WP-64 |
| M136 | نعم | حذف `watchdog=` من سطر session | SESSION-WATCHDOG | WP-71 |
| M137 | نعم | حذف الإلغاء عند `PEER_CLOSED` في authd | حالة ktest في 3.2 | WP-73 |
| M138 | لا | قبول `ui.lang` خارج القائمة | SESSION-AR | WP-72 |
| M139 | نعم | Value بأساس اتجاه الحوار (مشروط بـB1) | اختبار libui المضيف | WP-72 |
| M140–M142 | نعم | حذف البادئة `app:`، وحذف `job_kill` عند الخروج، وحذف القائمة البيضاء | LAUNCH-DENIED، LOGOUT-KILLS | WP-47 |
| M143–M144 | نعم | حذف فحص تسجيل SHELL، وإرسال الأحداث أثناء الحجب | SHELL-AUTHORITY | WP-48 |
| M145–M146 | نعم | classify بالنص بعد LFN، وحذف فحص وجهة rename | FAT-FUZZ، RENAME-AUTHORITY | WP-52 |

**تحديث 2026-11-09 (قرار المدير؛ السجلات حاكمة، والمعرّف يُثبَّت في tests/mutants.py عند الدمج):**
- WP-64 تأخذ M135 (تخطي التطهير) وM137 (حذف الإلغاء)، والإلغاء صار مقصورًا على عميل `session` (V2). 2026-11-10: M137 انتقلت مع الإلغاء إلى WP-73، وM150 (التطهير يفشل مفتوحًا) انتقلت من WP-71 إلى WP-64.
- WP-71 تأخذ M133 وM134 وM136، ومعها M148 وM149: always تُعامَل on-failure، وموعد المراقب عند 3W (الحد الأعلى 2W+1000 يقتلها، وعند 2W كانت تنجو؛ صُحّح 2026-11-10). M150 (التطهير يفشل مفتوحًا) انتقلت إلى WP-64 في 2026-11-10.
- WP-46 تأخذ M151-M153: job_kill بلا WRITE، وابن النداء 20 في المهمة الجذر، وحذف فحص المهمة المقتولة من spawn.
- WP-69 تأخذ M154-M156: حذف مرشّح الشجرة، وحذف فحص READ، وحذف فحص المؤشر.
- M147 لـWP-67، وM138-M139 تتبعان الشاشات إلى WP-72 ولم يُعَد قرارهما.
- 2026-11-10 (قرار المدير بعد تقارير التصميم): WP-68 تأخذ M157 (SECURITY) وM158 وM159 (SECURITY)؛ WP-77 تأخذ M160 وM161 (ليستا SECURITY)؛ WP-78 تأخذ M162-M164 (SECURITY)؛ WP-49 تأخذ M165-M167 وM168 (SECURITY) وM169؛ WP-79 تأخذ M170 (SECURITY)؛ WP-80 تأخذ M171 (SECURITY).

حذف فحص التوقيع في `fwcfg::read_file` (اقتراح redteam) لا قاتل له في pc-qemu، لأن التوقيع حاضر دائمًا تحت QEMU. لا يُكتب حتى يوجد له قاتل.

### 3.4 الهجمات التي يجب أن تصمد أمامها التصاميم

«demonstrated» تعني أن الهجوم ثابت بقراءة الشيفرة عند الرأس، وأكده التدقيق. ولم يُشغَّل أي هجوم.

| # | الهدف | الحالة | التحكم المعتمد | الاختبار |
|---|---|---|---|---|
| 1 | قرص الإصدار هو قرص المختبر: admin/lab-admin-1، وكل ELF، و`SVC-SH.TXT` (`project.py:980-1031`) | demonstrated | حد معلن في WP-45، وصورة release بلا حسابات بحارس يُكتب فاشلًا في أول هدف release (القسم 5.3، البند 3) | `TST-M9-RELEASE-NO-LAB-USERS` (NOT_RUN) |
| 2 | مفتاح fw_cfg يصير اسم بيان أو اختبار | hypothesis | قيمة ثابتة وثابتان مترجمان، وجدول ktest لا يُربط في الإصدار | مراحل INTERACTIVE-BOOT السلبية، M130 |
| 3 | لمس 0x510 و0xF4 على عتاد حقيقي | hypothesis | بوابة CPUID قبل fw_cfg في WP-45، وحراسة 0xF4 قبل Beta | حالة `-hypervisor`، وفحص ثابت لا يستدعي fwcfg خارج البوابة |
| 4 | الجلسة المعادة تكشف نوافذ المستخدم السابق | hypothesis (الآلية مؤكدة: `sessiond:783-801`؛ `display.md:42`) | تطهير عند البدء (WP-64)، وقتل مهمة الجلسة (WP-47) | `TST-M5-SESSION-LOSS` المرحلة 2 (صُحّح 2026-11-10)، M135 |
| 5 | رموز auth تبقى بعد موت الجلسة | hypothesis (الآلية مؤكدة: `authd:110-117` و`697-700`) | الإلغاء عند `PEER_CLOSED` | ktest في 3.2، M137 (WP-73 منذ 2026-11-10) |
| 6 | W قصير يقتل جلسة سليمة | hypothesis (المبدأ مؤكد) | قاعدة W في `session.md` | SESSION-WATCHDOG المرحلة 1 |
| 7 | PONG من الحلقات الداخلية يعطّل المراقب | hypothesis | PONG من الحلقة الرئيسية وحدها | فحص ثابت، M133 |
| 8 | given_up يحجب الدخول دائمًا | hypothesis | لا given_up دائم لسطر الجلسة (القسم 5.3، البند 10) | خمس عمليات قتل متتالية |
| 9 | `/APPS` قابل للكتابة لكل عملية (`vfs.rs:97-121`؛ `syscall/mod.rs:410-414`) | demonstrated | السجل تحت `/SYSTEM/APPS`، وقائمة بيضاء للتبعيات (ADR-0023) | LAUNCH-DENIED، M140–M142 |
| 10 | LFN واليونيكود يتجاوزان `/SYSTEM` | hypothesis | قرار السلطة على المجلد المحلول، ورفض النقاط والمسافات في الذيل، وطيّ ASCII أو اشتراط NFC | FAT-FUZZ، RENAME-AUTHORITY، M145 |
| 11 | rename يعبر حد السلطة | hypothesis | فحص المسارين ومجلدي الأب بحق WRITE | RENAME-AUTHORITY، RENAME-CRASH، M146 |
| 12 | طلب الرفع يُعرض في RTL بغير ترتيبه | hypothesis (غير مقيس) | B1 إن ثبت | اختبار libui، SESSION-AR، M139 |
| 13 | جداول عربية أو مقياس يقطع نصًا أمنيًا | hypothesis | لقطة إعدادات واحدة للقياس والرسم، وقصّ المقياس | `TST-M6-SESSION-STRINGS`، فرع SESSION-AR |
| 14 | تزوير أدلة PASS عبر فرع `ci-evidence/<id>` | demonstrated (ونشر التشغيلات الملغاة قيس) | فحص الاستيراد (WP-65)، وحماية الفروع (المالك) | حالات gh المزيف في `TST-M0-003` |
| 15 | المقيّم `tools/project.py` خارج مدخلات أحكام الضيف: 199 مدخلًا، ليس منها من `tools/` إلا `fat32.py` | demonstrated | المقيّم في ملف معزول يُضاف إلى `input_globs` (WP-66) | `TST-M0-007`: تعديل المقيّم يُقدِم أحكام الضيف |
| 16 | التقاط `PUSH_TOKEN` في خطوة النشر | hypothesis (البنية مؤكدة: `verify.yml:9-10` و`147-162`) | وظيفة publish منفصلة (WP-66) | `TST-M0-003`: الصلاحية العامة read، ووظيفة وحيدة بصلاحية write بلا checkout ولا tools/ |
| 17 | السلطة في الواجهة لا في الخدمة (WP-46/58/59/60) | hypothesis | الفحص في الخدمة أو النواة بهوية مضمونة | اختبارات DENIED بعميل خام |
| 18 | LOAD لبيان من مسار قابل للكتابة | hypothesis | مسارات LOAD ثوابت تحت `/SYSTEM`، والمدير يرفض ما خارجها | ktest في 3.2 |

### 3.5 إصلاحات الضمان بترتيب الأولوية

1. **فحص الاستيراد** (WP-65، القسم 2.8 REL-2). حرج على مستوى الأدلة.
2. **أصل الدليل 1.1.0 و`dirty_state`** (WP-65، REL-1 وREL-3).
3. **`stage_of` للمرحلة M6، وحارس المراسي، وحراس الأجنحة، و`SLOWEST_CLEAN_CASE_S`** (WP-65).
4. **فصل وظيفة النشر**: الصلاحية العامة `contents: read`، ووظيفة publish بصلاحية `contents: write` وحدها، لا تسحب الشيفرة، وتعمل بـ`git -c core.hooksPath=/dev/null` (WP-66، `ADR-0027` مقترح). شرطه معرفة حصة artifacts (غير متحققة).
5. **بوابة التقادم عند الإغلاق**: `check-commit` يعيد التحقق الصارم لاختبارات الحزمة المنتقلة إلى done. وحارس يقصر `stale_policy=warn` على `TST-M2..M5-MUTANTS` (WP-66، `TST-M6-STALE-GATE`).
6. **المقيّم داخل مدخلات أحكام الضيف** (WP-66).
7. **عدّ unsafe الواصل إلى الإصدار وعدّ `user/`** (WP-66، `TST-M0-008`). إلى أن يُنفَّذ: مدخل في نموذج التهديد وسطر ADR في WP-45.
8. **سجلات RC** في إيداع سجلات مستقل لا يحجب WP-45:
   - `ADR-0025` و`docs/defects.json` لمعيار الشدة.
   - `evidence-verdict` 1.1.0 بحقول المراجع: `reviewer_id ≠ worker`، و`image_digest`.
   - REQ/TST-M10 لـ22.4.
   - إعادة تقييم `DEC-004`: فحص كل الإيداعات بـ`fetch-depth: 0`، ورفض أي `WP-xx` في العنوان لحزمة planned (`project.py:1478`).

---

## 4. تغييرات السجلات

القائمة مرتبة بالإيداعات، وكل عنوان مفحوص مقابل `DEC-004` (`project.py:1478-1500`).

### K0: «Checkpoint 59 at 5f48703c» (بلا حزمة)

| السجل | التغيير | السبب | الحاجب |
|---|---|---|---|
| `docs/project-state.json` | `checkpoint` فيصبح الجيل 59، و`source_revision=5f48703c`، و`current_task=WP-45` | الشرط 2 مفتوح، والتحذير الوحيد «checkpoint pending» | تسمية الكاتب الوحيد (القسم 5.3، البند 1). `project.py:1468-1469` يحدّث `fencing_token` ولا يفحص انقضاء العقد |

### C1: «Records: split WP-45 per its budget line and ADR-0019:48; WP-64 and WP-65 planned» (سجلات فقط)

| السجل | التغيير | السبب | الحاجب |
|---|---|---|---|
| `docs/project-state.json` | `pending_decision_ids=[DEC-002, DEC-023]`، و`lease=null` مع سبب في `unknown_fields` | DEC-023 open وغائب، والعقد منتهٍ ولا أداة تكتسبه | لا شيء بعد القسم 5.3 البند 1 |
| `docs/automation.json` | `lease_policy`: «غير منفذ؛ كاتب واحد» | لا ملف `state/lease.json` | لا شيء. هل هو مدخل لدليل M0؟ غير متحقق |
| WP-45 | `test_ids`: `[TST-M6-INTERACTIVE-BOOT, TST-M6-MANIFEST-LINT, TST-M6-HOLD-FAIL-CLOSED, TST-M1-BOOT, TST-M1-NEG, TST-M1-NOBS, TST-M0-003, TST-M0-005, TST-M5-LAB-TOOL]`. `contract_refs`: `[services.md, boot.md]`. تُحذف `actions[2]` والشق العربي من `[3]` و`[4]`. يُضاف سطر مؤرخ 2026-11-09: «split per actions[5] and ADR-0019:48; watchdog and Arabic screens moved to WP-64». يبقى `[5]`، ويُضاف إليه: «إن تجاوز التقدير عند التفعيل، يخرج أولًا HOLD-FAIL-CLOSED وإصلاح displayd إلى حزمة قبل WP-47». القبول: «TST-M6-INTERACTIVE-BOOT PASS on CI; TST-M1-BOOT PASS under the self-test key; TST-M1-NEG and TST-M1-NOBS re-run unchanged and PASS». تُحذف عبارة M5، لأن أحكام M5 تتقادم بتعديل النواة فيفرضها `--strict` عند الإغلاق (`project.py:169-175`). ويُضاف حد قرص المختبر. تبقى planned | القسمة، والقبول الحالي يدّعي ما لا ينطبق على NEG وNOBS (مؤكد) | لا شيء |
| WP-64 (جديد، في آخر records) | stage M6، و`requirement_ids=[REQ-M6-002]`، و`depends_on=[WP-45]`، و`contract_refs=[session.md, config.md, input.md, services.md, ui.md, auth.md]`. `actions`: البنود المنقولة حرفيًا من WP-45، وسطر قسمة، وسطر ميزانية بنقطة قسمة ثانية (المراقب والتطهير والإلغاء / الشاشات العربية)، والشروط المؤكدة في القسم 2.3. `test_ids`: `[TST-M6-SESSION-WATCHDOG, TST-M6-SESSION-AR, TST-M6-SESSION-STRINGS, TST-M6-INTERACTIVE-BOOT, TST-M5-ELEVATE, TST-M5-SVC-WATCHDOG, TST-M5-UI-UNIT, TST-M5-ARABIC-UI, TST-M5-LOGIN-SCREEN, TST-M5-AUTH-INPUT-ISOLATED, TST-M5-LOCK-SURVIVES, TST-M5-LOCK-HANG, TST-M5-SESSION-HANG]`. status planned، و`status_history=[planned]`، و`evidence_refs=[]`، و`blocker=""` | المعرّف غير مستعمل، والإلحاق في الآخر لا يغيّر `derive_position` (`project.py:1436-1442`) | لا شيء |
| WP-65 (جديد، في آخر records) | stage M6، و`requirement_ids=[REQ-M0-006]`، و`depends_on=[]`، و`test_ids=[TST-M0-001, TST-M0-003, TST-M0-005, TST-M0-007]`، والنطاق في القسم 2.8 و2.5 (D5 وD6 وD7)، وسطر ميزانية بنقطة قسمة (الاستيراد والهوية / الطفرات والحراس) | الاستيراد بلا فحص، ونشر التشغيلات الملغاة مقيس | لا شيء. المدقق لا يمنع حزمة M6 بمتطلب M0 (`project.py:236` و`289`) |
| WP-47 | `depends_on=[WP-46, WP-64]` | القسم 1.2 | لا شيء |
| WP-49، WP-50، WP-63 | وعود `ui.md` إلى v1.7 وv1.8 وv1.9 (صُحّح 2026-11-10: v1.6 وv1.7 وv1.8؛ ثم 2026-11-10: ui.md v1.7 لـWP-80، وWP-50 v1.8، وWP-63 v1.9) | الترقيم n1. الوعود تُفحص للحزم active وdone فقط (`project.py:300-309`) | لا شيء |
| WP-51 و`REQ-M6-007` | إضافة `TST-M6-RTC-READ` إلى `test_ids` | المتطلب بلا حَكَم للساعة | لا شيء |
| `docs/tests.json` | `TST-M6-SESSION-WATCHDOG` و`TST-M6-SESSION-AR`: «WP-45» تصبح «WP-64»، والتقويات في القسمين 2.3 و2.4. `TST-M6-INTERACTIVE-BOOT`: يُستبدل «expected regions» بفحوص `screen.py desktop --pixel/--ink` (`screen.py:135-148`)، ويُضاف `reply=OK 8` و`held=1` و`ends_by` والمراحل السلبية. البادئ `planned` يبقى في الثلاثة | المدقق يمنع PASS مع planned (`project.py:291-294`) | لا شيء |
| `docs/tests.json` (جديد، NOT_RUN، أوراكل planned) | `TST-M6-MANIFEST-LINT`، و`TST-M6-HOLD-FAIL-CLOSED`، و`TST-M6-SESSION-STRINGS` (`requirement_ids=[REQ-M6-002]`)، و`TST-M6-RTC-READ` (REQ-M6-007)، و`TST-M0-007` (REQ-M0-006) | حَكَم لكل قرار | لا شيء |
| `docs/requirements.json` | `REQ-M6-002.test_ids` تضيف الجديدة، والنص والقبول دون تغيير، والحالة تبقى planned. `REQ-M0-006` جديد: «أصل الدليل وفحص الاستيراد» | الربط بين المتطلب والاختبار في الاتجاهين لا يُفحص آليًا (`project.py:236` و`272`) | لا شيء |
| `docs/PLAN.md:122` | المسار الحرج: «WP-45 ← (46 ∥ 64) ← 47 ← 48 ← 51 ← 52 ← 53 ← 55 ← 57 ← 59 ← 62»، وصف WP-45، وصفوف WP-64 وWP-65، وترقيم ui.md | المسار القديم يمر بـWP-56 (مؤكد) | لا شيء |
| `docs/stages.json:308` | يُوسَّع شرط نموذج التهديد ليشمل نمط الإقلاع وبيان النظام، ومراقبة الجلسة، وشاشات الرفع العربية | يسمي أربعة موضوعات فقط (مؤكد) | لا شيء |
| `docs/PLAN-ANSWER.md` | هذه الوثيقة | `CLAUDE.md:3` | لا شيء |

بعد C1 يُشغَّل `tools/pre-merge.sh`، ويجب أن يعطي 0 أخطاء.

### W0–W3: حزمة الضمان WP-65

| الإيداع | المحتوى |
|---|---|
| W0 «WP-65: activate» | status active، ثم checkpoint |
| W1 «WP-65: failing tests for import check, evidence provenance 1.1.0, dirty_state, stage_of M6, anchors and suite guards» | الاختبارات في القسم 2.8، و`stage_of('M130')=='M6'`، و`--stage M6`، و`test_every_anchor_occurs_once`، و`test_every_guest_suite_runs_in_verify`، و`test_every_host_suite_is_nonempty_and_runs_in_verify`، و`SLOWEST_CLEAN_CASE_S=137`. خرج الفشل مسودة، ولا يُدفع منفردًا |
| W2 «WP-65: import check, evidence-run 1.1.0 with import.json, dirty_paths; mutants stage M6» | `tools/project.py`، و`docs/schemas/evidence-run.schema.json`، و`tests/mutants.py` (`stage_of`، و`choices`، والـdocstring في السطر 24)، و`docs/adr/0026-evidence-provenance.md`، وأوراكل `TST-M0-003` و`TST-M0-005` و`TST-M0-007`. ثم الدفع |
| W3 «WP-65: close» | `import-ci-evidence --run <id>` بالأداة الجديدة، ثم done مع `evidence_refs`، ثم `--strict` = 0، ثم checkpoint |

### C2–C6: WP-45

| الإيداع | المحتوى | الحاجب |
|---|---|---|
| C2 «WP-45: activate (boot mode and the system manifest)» | status active، و`status_history=[planned, active]`، وسطر تقدير مؤرخ مقابل 90 دقيقة أو 120 استدعاءً (prompt:71) مع عدادات تُحمل ولا تُصفَّر (prompt:73)، ثم checkpoint | WP-65 done، والمراجعة بعد القسم 5.3 |
| C3 «WP-45: services.md v1.11 and the boot-mode decision in boot.md; PLAN-REVERSE §2 refreshed» | `services.md` من 1.10 إلى 1.11. `boot.md`: النمط، والمفتاح، والبوابة (CPUID ثم التوقيع، والبديل OEMID بعد القياس)، وحد قرص المختبر. `threat-model.md`: القسم 3.1. `ADR-0019:48`: سطر التصحيح. `PLAN-REVERSE.md`: يُحدَّث §2، ويُصحَّح السطر 7 من 321-324 إلى 329-331، و§4.2 بند 5 من dece70c2 إلى 61e65bf1، و`M146/M147` إلى التوزيع في 3.3، والشرط 7 (المهلة FAIL، والالتباس في الرمز 0) | لا شيء |
| C4 «WP-45: failing tests …» | `target.json`: `suites['M6']`، و`qemu_extra` على `TST-M1-BOOT` و`boot_oracle`. أوراكل `TST-M1-BOOT` يصير `/SYSTEM/SELFTEST.TXT` مع وسم `mode=selftest`، ويُعاد تشغيله. `project.py:1053` و`select_boot_case`. `HOST_SUITES['M6']` و`tests/test_m6_manifest.py`. `verify.yml`: خطوة الضيف M6، وخطوة مضيف M6، والسقوف، والحد 55. «16 cases» في `tests.json` و`project.py:1205`. أوراكل `TST-M5-LAB-TOOL` يصير 10 حالات، و`ends_by`. الطفرات M130–M132 | قياس مسودة محلي لرمز `quit` |
| C5 «WP-45: interactive boot path; lab self-test behind the fw_cfg key» | `kernel/src/bootmode.rs`، و`kmain.rs`، و`mod.rs`، و`fwcfg.rs`، و`services.rs`، والبيانان، وإصلاح `displayd` للفشل المغلق. ثم الفحوص المحلية، ثم الدفع مع C4 | لا شيء |
| C6 «WP-45: close» | verify كامل أخضر، ثم الاستيراد المفحوص، ثم WP-45 done، ثم `REQ-M6-002` partial (المخطط يسمح بها)، ثم `--strict` = 0، ثم checkpoint | بت المشرف مقيس على CI. إن كان صفرًا تُعتمد البوابة البديلة ويُعدَّل `boot.md` قبل الإغلاق |

### فحص الميزانية

ما يلي من قائمة المساعد، بلا قياس:
- WP-45 غير مقسومة لا تتسع على الأرجح.
- WP-45 بعد القسمة نحو 15 إلى 20 ملفًا، وهذا تقدير.
- WP-45 تضيق بالإضافات المقبولة هنا: MANIFEST-LINT، وHOLD-FAIL-CLOSED، و`ends_by`، والسقوف. لذلك أُخرجت تعديلات الأدوات الأخرى إلى WP-65 وWP-66، وسُمّيت نقطة القسمة الأولى داخل WP-45.
- verify الكامل نحو 29 دقيقة. هل يُحسب انتظار CI من زمن الأوامر في prompt:71؟ غير محسوم في السجلات.
- `budget_counters.tool_calls_session=null`، فشرط prompt:73 غير قابل للإثبات اليوم.
- WP-64 تحمل نقطة قسمة ثانية تُقرأ عند تفعيلها.

---

## 5. ما رفضه التدقيق أو لم يتحقق

### 5.1 الادعاءات المردودة

| # | الادعاء ومصدره | سبب الرد |
|---|---|---|
| 1 | تشغيل `42627452529` معلّق (المخططون) | `gh run view`: completed/success على `9ceb133a`، والفرع منشور (`34caafd2`). وتقدّم الرأس إلى `5f48703c`، فـC0 منجز |
| 2 | `42623295604` in_progress (المخططون) | ملغى. وكذلك `42627392129` و`42623032466`، وللملغيين `42623295604` و`42623032466` فرعا أدلة منشوران |
| 3 | «لا يخرج» قد يمر نجاحًا زائفًا بالمهلة (السلسلة) | 124 يعطي FAIL «timeout (hang)» (`project.py:1169-1170`). الخطر الحقيقي التباس الرمز 0 بين `quit` وإعادة الضبط |
| 4 | الطفرات التي حاكمها `TST-M1-BOOT` تُقتل زورًا عبر `project.py boot` (sw-kernel، عالٍ) | `run_killers` يستعمل `test --suite --only` (`mutants.py:719-733`). المكسور خط أساس `mutants.yml:45`. والـdocstring في `mutants.py:24` يصف مسارًا لم يعد قائمًا |
| 5 | صورة الإصدار تكتب 0xF4 في `kmain.rs:105` (sys-platform) | السطر 105 في مسار aarch64 بـsemihosting (`arch/aarch64/qemu.rs:17-25`). السطر الصحيح على x86 هو 572 |
| 6 | علاج ترتيب الطلب بعزل LRI…PDI (sec-threat) | `TEXT_MAX=48` (`libui lib.rs:25`)، والطلب الأقصى 15+1+32=48، فلا مكان للمحرفين |
| 7 | «تضيف الجلسة config إلى تبعياتها (sessiond:58)» (sec-threat) | إضافتها إلى `DEPS` تمنع `ELEVATE config` (`main.rs:1284`). الصحيح: تبعية في البيان واتصال اختياري خارج `DEPS` |
| 8 | SESSION-AR يفشل لأن الشاشتين بالإنجليزية (`session.md:103`) | السطر 103 «مستخدم واحد في كل مرة»، والحد الإنجليزي في 104 |
| 9 | أحكام PASS تمر من تشغيل فشلت فيه hygiene (sec-assurance) | خطوة hygiene والأجنحة بعدها بلا `if: always()`، ففشلها يُسقط الأجنحة. يصح الادعاء لفشل جناح لاحق، أو `--strict`، أو الإلغاء |

### 5.2 غير قابل للتحقق

| الادعاء | السبب | ما يلزم |
|---|---|---|
| `--strict` عند `9ceb133a` يعطي 17 خطأ | الرأس تحرك قبل القياس. عند `5f48703c`: 0 أخطاء (مسودة) | لا شيء. الشرط 1 سليم محليًا، والحكم لـCI |
| إزاحات FADT (CENTURY@108، IAPC_BOOT_ARCH@109، Flags@112، RESET_REG@116، RESET_VALUE@128، bit 10، bit 5)، وقيم QEMU 8.2.2 (0xCF9، 0xf، `_S5={0,0,0,0}`) | لا مصدر في `sources.json` يغطي §5.2.9. الاستخراج آلي لا حرفي | قراءة حرفية تُسجَّل في `S33`، وتسجيل مصدر QEMU قبل `syscall.md` v1.14 |
| QEMU TCG مع `cpu=qemu64` يعرض `CPUID.1:ECX[31]` | لا قياس ولا مصدر | حالة ktest تطبع البت على CI قبل البوابة |
| إعادة ترتيب bidi لطلب ASCII في RTL | لم يُشغَّل شيء | اختبار libui المضيف قبل اختيار العلاج |

### 5.3 التناقضات التي حسمها المدير

| # | التناقض | الحسم والسبب |
|---|---|---|
| 1 | كاتبان مع عقد منتهٍ (5f48703c)، مقابل REL-5 A بكاتب واحد | دور المدير هو الكاتب الوحيد للسجلات في هذه الدورة، وكل الأدوار الأخرى قراءة فقط كما في هذا التشغيل. `lease=null` مع السبب. تنفيذ prompt:79 متطلب مؤجل شرطه أن يسبق أي كتابة متوازية. هوية كاتب `5f48703c` غير معروفة، وتُرفع إلى المالك (القسم 6) |
| 2 | ترتيب S1: المخططون C0 ثم C1 ثم C2، مقابل S1 أولًا | WP-65 بعد C1 وقبل C2. الكلفة دورة verify واحدة. البديل يغلق WP-45 باستيراد غير مفحوص، ونشر التشغيلات الملغاة صار مقيسًا |
| 3 | قرص الإصدار بلا `lab.users` (redteam)، مقابل أوراكل INTERACTIVE-BOOT يدخل بحساب user | قرص واحد في WP-45 مع حد معلن في `boot.md` و`threat-model` («قرص مختبر، ليس صورة إصدار، غير صالح لعتاد حقيقي»). صورة release والحارس يُكتبان فاشلين في أول هدف release (REL-4 B). السبب: لا هدف release اليوم، و`NAWAH.EFI` لا يحمل المستخدمين، والأوراكل يحتاج الحسابات. يُسجَّل `RSK-017` (مقترح) |
| 4 | الهوية 1.1.0: import.json (release)، أو كتابة فوق run.json (assurance)، أو `worker=ci-verify` (redteam) | REL-1 C: `import.json` جانبي، و`run.json` لا يُمس، و`worker` من التعداد. الكتابة فوق `run.json` تكرر عيب تعديل الدليل بعد إنتاجه (`project.py:1531`). و`verification-runner` يطابق `automation.json:4-18`. ثغرة المقيّم خارج المدخلات تُسد في WP-66 |
| 5 | بوابة المحاكي: CPUID ثم التوقيع، أم ACPI OEMID/QEMU0002، أم SMBIOS | CPUID ثم التوقيع، بشرط القياس أولًا. البديل المسجل OEMID. SMBIOS غير مختار. السبب: ثلاثة أدوار، وأرخص كلفة (Rust آمن، `mod.rs:72-73`) |
| 6 | نطاق حراسة 0xF4: داخل WP-45 لكل المسارات، أم قبل Beta، أم مسار الفحص الذاتي وحده | خارج WP-45، بند قبل Beta مسجل خطرًا. قصرها على مسار الفحص الذاتي يحوّل panic تحت QEMU إلى مهلة ويضيع `EXIT_PANIC=35`. و`stub.rs:38` قبل EBS لا يقرأ fw_cfg، و`TST-M1-NEG` يعتمد على الرمز 97. في WP-45 تحرس البوابة قراءة fw_cfg وحدها |
| 7 | اسم البيان الفارغ: SELFTEST.TXT أم LABEMPTY.TXT أم SERVICES.TXT الفارغ (redteam) | `SELFTEST.TXT`، وهو اسم 8.3 صالح، ومعناه مختبري، واقترحه دوران. SERVICES.TXT الفارغ يناقض M-a وأوراكل INTERACTIVE-BOOT |
| 8 | توقيت `HOST_SUITES['M6']` | القاعدة: مع أول حالة مضيف. والأولى `TST-M6-MANIFEST-LINT` في WP-45، فيُنشأ الجناح وخطوته في C4. حارسا D5 في WP-65 قبله |
| 9 | رفع `ui.md`: يلزم في WP-64 (apps) أم لا (services) | يُسجَّل n1 الآن، وهو سجلي رخيص قابل للعكس. الرفع يلزمه الشارة I-3 على أي حال. وB1 مشروط بالاختبار. المؤشر يقرأ STATUS بلا رفع لـ`input.md`، وفي هذا اتفق الدوران |
| 10 | given_up: إخفاق مغلق مقبول (services)، أم حجب دائم يطلقه تطبيق غير مميز (redteam) | `session.md` v1.7 ينص على أن given_up الدائم غير مقبول لسطر الجلسة. الاختيار بين عدد إعادات كبير بدلالات السياسة القائمة وبين backoff في svcmgr يُحسم في WP-64 بعد قراءة شيفرة الإعادة في svcmgr، وهي لم يقرأها أي دور. الحَكَم: خمس عمليات قتل ثم دخول ناجح |
| 11 | معامل W: 4D أم 3D | العقد يكتب القاعدة، والرقم يُقاس. القيمة المبدئية 25000 |
| 12 | علاج RTL: LRI/PDI، أم B1، أم تقصير الحد | LRI/PDI مردود. B1 إن ثبت بالاختبار. وتقصير الحد (تعديل `session.md`) احتياطي |
| 13 | config والجلسة | تبعية في سطر session في البيان، تكتبه WP-45. واتصال اختياري خارج `DEPS` في WP-64 |
| 14 | تصادم المعرّفات المقترحة | WP-64 للمراقب والشاشات، وWP-65 للضمان 1، وWP-66 للضمان 2. الطفرات بحسب الجدول 3.3. `REQ-M0-006` أصل الدليل وفحص الاستيراد. `TST-M0-007` اختباراته، ومنها حالة تقادم المقيّم. `REQ-M0-007` فصل النشر. `TST-M0-008` عدّ unsafe لـ`user/` ولما يصل إلى الإصدار، فلا يُستعمل `TST-M0-009`. `ADR-0023` سجل التطبيقات (محجوز في الخطة)، و`ADR-0025` الشدة، و`ADR-0026` أصل الدليل والاستيراد، و`ADR-0027` فصل النشر، و`ADR-0028` هوية الصورة وSBOM. DEC-012..021 كما في السلّم، و`DEC-022` ترخيص المشروع. RSK-012..016 كما في السلّم، و`RSK-015` يجمع DMA وCOM2، و`RSK-017` قرص المختبر، و`RSK-018` تبعيات الجلسة الصلبة، و`RSK-019` فجوة تعريفات العتاد الحقيقي |
  - **ملاحظة مؤرخة 2026-11-09:** سُجِّل RSK-019 فعلًا في docs/risks.json بمعنى آخر (سلطة config غير المقيدة على /SYSTEM، من مراجعة الفريق الأحمر لـWP-45)، فالمقترح هنا بمعنى «فجوة تعريفات العتاد الحقيقي» يأخذ المعرّف الحر التالي عند تسجيله (مقترح R2 في docs/proposals/PLAN-R2-PROPOSAL.md يبدأ من RSK-020).
| 15 | مرحلة حزمة الضمان | M6. المدقق لا يربط مرحلة الحزمة بمرحلة المتطلب، فالقرار تنظيمي. وM6 هي المرحلة المفتوحة |
| 16 | إلغاء رموز authd: داخل WP-64 أم خارجها | داخلها، لأن المراقب يضيف طريق القتل. ونقطة القسمة الثانية تفصل المراقب والتطهير والإلغاء عن الشاشات |
| 17 | خطة C1–C6 لا تتضمن stages.json:308 ولا ترقيم ui.md ولا السجلات الجديدة | أُدرجت في C1 (القسم 4) |

---

## 6. ما يتوقف على المالك

| القرار | ما يحجبه | الإجراء المطلوب من المالك بالضبط |
|---|---|---|
| كاتب `5f48703c` | K0 | يذكر من أي جلسة صدر `5f48703c`، ويوقف أي كتابة سجلات خارج دور المدير حتى ينفَّذ prompt:79 |
| مصادقة gh للاستيراد | W3 وC6 بعد فحص الاستيراد | يوفّر `gh` مصادقًا في الجلسة التي تستورد، وإلا يعطي الاستيراد `E_BLOCKED` |
| `DEC-002` | M7، وMVP، وأحكام «مطابقة للمرجع» | يثبّت Windows 10 Pro 22H2 مرخصًا في VM ويشغّل عدة الالتقاط وفق ADR-0022 قبل فتح M7، أو يوقّع استثناءً بصيغة 22.1 يسمي المتطلب والسبب والأثر والتعويض ومدة الصلاحية |
| `DEC-023` | لا حزمة | يكتب «اقفل على ADR-0002 §4»، أو يتيح `sol-os-phase2.zip` لجلسة سحابية |
| تفويض 2026-11-08 | WP-47، 48، 51، 53، 55، 62، 63 | يسجّل نص التفويض ونطاقه وصاحبه في ملف تحت `docs/operations/`، أو يمليه ليُنسخ حرفيًا |
| `DEC-007` (S5) | WP-51، M6، Beta | يحدد مرحلة ACPI S5 (المقترح M8)، والتعويض (إعادة تشغيل منظمة تحفظ البيانات، ولا عنصر إيقاف في القائمة)، ومدة الصلاحية |
| `DEC-009` | WP-48، WP-62، M7 | يحدد صلاحية الاستثناء حتى نهاية M6 وتعويضه، مثل «لا ادعاء مطابقة في أي نص منتج» |
| `DEC-003` | WP-62 | يوقّع حكم مراجعة M6 على صف M1 في `decisions-pending.json:49`: مغلق باختبار مسمى، أو استثناء بتعويض ومدة |
| `DEC-012` الأيقونات | WP-48، `TST-M6-ASSET-PROVENANCE` | يسمي مصدر الأيقونات (الفريق، أو مصممًا باسمه، أو مجموعة بترخيص محدد) وترخيصها قبل تفعيل WP-48 |
| `DEC-013` الجهاز الحقيقي | M8، Beta، RSK-007، المسبار | يسمي جهازًا واحدًا وطرازه وإصدار برنامجه الثابت، ويكتب تفويضًا بالإقلاع من USB دون كتابة على القرص الداخلي، ثم تفويضًا منفصلًا بالكتابة على قرص محدد إن لزم |
| `DEC-014` المراجع المستقل | Beta (`threat-model.md:95`)، و22.6 | يحسم نوع المراجع (شخص أو جلسة وكيل مستقلة) لكل من Beta و22.6، ويسميه، ويمنحه وصول قراءة فقط |
| `DEC-015` الشدة | M10، و22.3 | يوقّع ADR-0025 (الدرجات ومعاييرها) قبل فتح M10 |
| `DEC-016` المفاتيح | M9، و22.4، و22.7 | يقرر أين تُحفظ مفاتيح توقيع الإصدار ومن يملكها ومن يبطلها، خارج المستودع وخارج رموز CI، قبل فتح M9 |
| `DEC-017` Secure Boot | Alpha، RC | يقرر قبل M10: داخل R1، أو استثناء بصيغة 22.1 بتعويض ومدة |
| `DEC-018` Alpha وM8 | ترتيب M8 وM9 | لا إجراء، إلا إن أراد Alpha قبل M8 فيكتب «تُعدَّل تبعية M9» |
| `DEC-019` حماية الفروع | سلامة الأدلة حتى RC | يفعّل حماية `main`، ويقصر `ci-evidence/**` على github-actions بلا حذف ولا دفع قسري |
| `DEC-020` توافق Windows | M8 | يحدد قبل M8 مستويات التوافق الداخلة في النطاق، أو يكتب «لا شيء في R1» |
| `DEC-021` النشر والصيانة | M11، و22.7 | يكتب قبل M11 هل يُنشر الإصدار خارجيًا وأين، ومن يملك الصيانة والاستجابة للبلاغات |
| `DEC-022` ترخيص المشروع (مقترح) | REL-6، و22.4 | يختار ترخيص المشروع. لا يوجد `LICENSE*` في المستودع |
| sh على COM2 في صورة Beta | RSK-015 | يقرر قبل Beta: صورة بلا sh، أو sh خلف جلسة |
| حصة artifacts | WP-66 (فصل النشر) | يؤكد حصة artifacts في حساب GitHub. هي غير متحققة، وتحتاجها WP-66 |
| قراءة ACPI الحرفية (اختياري) | `syscall.md` v1.14 | يسمح بالوصول إلى `uefi.org` في شبكة الجلسة، والبديل Firecrawl |
| الدمج إلى `main` | كل حزمة | تقديم سريع للإيداع الذي تحقق منه CI، بيد المالك |

---

## 7. حدود هذه الإجابة

- **التاريخ:** 2026-11-09. **الرأس:** `5f48703c`. كُتبت الإجابة أثناء تشغيل تقدّم فيه الرأس من `9ceb133a` إلى `5f48703c`، ونتيجة CI على `5f48703c` نفسه لم تُقرأ.
- **لم يُشغَّل QEMU ولا أي جناح.** كل التشغيلات المحلية (`validate-records`، و`check-commit`، وعدّ الأدلة، وفحص المراسي عند `9ceb133a`) مسودة لا دليل.
- **لم يُقس:**
  - بت المشرف تحت TCG.
  - رمز خروج QEMU عند `quit`.
  - زمن INTERACTIVE-BOOT.
  - مهلة LOAD لثماني خدمات.
  - طول جواب LIST مقابل 1024 بايتًا.
  - معامل W.
  - إعادة ترتيب bidi.
  - أبعاد الشاشات خارج حساب النموذج.
  - زمن M6 على CI.
  - الحجوم مقابل الميزانية، فكل التقديرات بعدد الملفات.
- **لم يُقرأ:**
  - `config.md` و`auth.md` كاملين، فصلاحية الكتابة على مخزن device غير متحققة.
  - شيفرة الإعادة في svcmgr، ومسار LOAD لملفات خارج `/SYSTEM`.
  - خوارزمية الاتجاه في Painter.
  - سلوك displayd لـUNLOCKED بعد جلسة جديدة (اعتُمد العقد).
  - البنود 11 و12 و14 من البرومبت كاملة.
  - فصل Secure Boot في `S11`.
  - `work-items.json:3179`.
  - الحماية الكلاسيكية للفروع (أعاد الطلب 403). rulesets أعاد `[]`، وعدد فروع `ci-evidence` 269 عند القراءة.
- **غير متحقق أيضًا:**
  - قبول authd لكلمة مرور عربية.
  - بناء crate جديد للمضيف تحت build-std.
  - مصدر النصوص الإنجليزية الحالية للجلسة (`sessiond main.rs:403-423`).
  - قابلية التقاط `PUSH_TOKEN`.
  - أن mtime هو السبب الوحيد لاعتماد WP-52 على WP-51.
  - هل `automation.json` مدخل لدليل M0.
  - هل يرفض المدقق متطلب M0 في حزمة M6 لاحقًا.
- **المعرّفات الجديدة كلها مقترحة**، ووُحّدت في القسم 5.3 البند 14: WP-64/65/66، وM130–M146، وREQ/TST الجديدة، وADR-0025..0028، وDEC-012..022، وRSK-012..019. تُثبَّت في الإيداع الذي ينشئها.
- **الغرفة النظيفة:** لم يجد التدقيق انتهاكًا لـADR-0022. المصادر المستعملة مواصفات منشورة (ACPI، وUAX #9، وSPDX/CycloneDX) وشيفرة QEMU. والنصوص العربية الجديدة يجب أن تحمل رأس مصدر.
- **لا اقتراح هنا يُضعف بوابة.** تغيير مسار وسم `TST-M1-BOOT` يبقي `reply=OK 0` وبقية الأوسمة ورمز الخروج 33.