# عقد الـ shell التشخيصي — الإصدار 1 (WP-30، ADR-0018؛ فوق services.md v1.3 وauth.md v1 وnet.md v1 وfiles.md v1.1 وsyscall.md v1.7)

مجمَّد (أُغلق WP-30 بدليل CI run 39141804574): أي تغيير في الأوامر أو البروتوكول أو القناة = إصدار جديد مع سجل قرار؛ الإضافات إضافية فقط. الكود: `user/apps/sh` (الخدمة `sh`)، `kernel/src/arch/x86_64/com2.rs` (COM2)، `kernel/src/diag.rs` (الاستطلاع والكتابة)، `kernel/src/object/bytes.rs` (الكائن)، `tools/project.py` (`ConsoleSession`: جلسة المختبر)، `tests/test_console_session.py` (اختبار الأداة على المضيف).

## 1. النموذج

- **خدمة مستخدم** `sh` (`/SYSTEM/SH.ELF`) يبدؤها المدير من البيان؛ مقابضها الأولية: قناة الإقلاع (`rdi`) وقناة التشخيص (`rdi + 1`، `Object::Serial` — syscall.md §6). لا سلطة محيطية: ما تعرضه يأتي من **مالكه** عبر القنوات أو النداءات، لا من ذاكرة الـ shell: الخدمات من المدير (`LIST` على قناة الإقلاع)، الشبكة من الخدمة `net`، عدّادات النواة من `system_info`، الملفات من الحجم. وما تصل إليه من خدمات تحدده تبعياتها في البيان (services.md §4: `CONNECT` لتبعية معلنة فقط).
- **القناة**: COM2 (16550 في 0x2F8، 115200 8N1) تُستطلع من نبضة المؤقت (ADR-0017/0018) إلى حلقة 256 بايت؛ في المختبر تخرج إلى مقبس TCP على المضيف (`-serial tcp:127.0.0.1:<port>,server=on,wait=off`)، وفي غير حالات الـ shell إلى `null` فالجهاز موجود دائمًا ويُفحص بالإقلاع (`kernel|diag|port=0x2f8|present=1|ring=256|code=ok|selfcheck=1`).
- **الأسطر**: الأوامر أسطر تنتهي بـ LF (CR يُتجاهل) حتى 256 بايت؛ الأطول يُرفض كله بـ `ERR LINE_TOO_LONG`. كل سطر إخراج ينتهي بـ LF، ثم **المحثّ** بلا LF: `nawah> ` بلا جلسة أو `<user>@nawah> ` بجلسة مفتوحة. عند البدء: `nawah sh 1 (help)` ثم المحثّ.
- **الجلسة**: `login` يحصل على رمز من الخدمة `auth` (auth.md §2) يحمله الـ shell باسم المستخدم؛ الأوامر المحمية ترسل **نسخة** منه (`handle_duplicate`) مع طلبها — المقبض في الرسالة يُنقل لا يُنسخ (ipc.md §3) والخدمة تغلق ما استلمته — والخدمة المالكة هي التي تفحص الصلاحية (لا رفع صلاحية بتمرير نص: OS-EXEC-AR §12). `logout` يُبطله (`LOGOUT`) ويغلقه. جلسة واحدة في آن.

## 2. الأوامر

| الأمر | ما يفعل | الإخراج |
|---|---|---|
| `help` | قائمة الأوامر | سطر `commands: …` |
| `svc` | `LIST` من المدير | أسطر `name state restarts first last ready exit` كما في services.md §3 |
| `cpu` | `system_info` | `cpus=<n> ticks=<t> processes=<p> threads=<t>` |
| `mem` | `system_info` | `frames_total=… frames_free=… heap_live_bytes=… heap_pages=… handles=… channels=…` |
| `net` | `STATUS` من `net` | ردّ الخدمة حرفيًا (net.md ب) |
| `net dhcp` | `DHCP` من `net` | ردّ الخدمة |
| `net policy internet=<0/1>` | `POLICY …` + رمز الجلسة إلى `net` | ردّ الخدمة (`OK` / `ERR ACCESS`)؛ بلا جلسة `ERR NO_SESSION` |
| `ls [path]` | `dir_list` (الافتراضي `/`) | أسطر files.md §2؛ أخطاء: `ERR NOT_FOUND`/`NOT_DIR`/`BAD_PATH`/`TOO_LARGE` |
| `cat <path>` | `open`+`read` حتى 4095 بايت | المحتوى (يُلحق LF إن لم ينتهِ به)؛ `ERR NOT_FOUND`/`IS_DIR`/… |
| `login <user> <password>` | `LOGIN` إلى `auth` | `logged in as <user>` والمحثّ `<user>@nawah> `؛ `login failed: <ردّ auth>` (مثل `ERR ACCESS`)؛ بجلسة مفتوحة `ERR SESSION_OPEN` |
| `whoami` | `WHOAMI` + الرمز إلى `auth` | `<user> OK <uid> <gid> <perms>`؛ بلا جلسة `not logged in` |
| `logout` | `LOGOUT` + الرمز | `logged out`؛ بلا جلسة `not logged in` |
| `exit` | إنهاء الخدمة بصفر | `bye` (المدير يراها `stopped`) |
| غير ذلك | — | `ERR UNKNOWN_COMMAND` |

- تعذّر الوصول إلى المدير أو خدمة: `ERR MANAGER` / `ERR SERVICE` / ردّ المدير (`ERR ACCESS` لخدمة ليست تبعية، `ERR NOT_READY`، `ERR UNKNOWN`). انتظار الردّ محدود بـ 10000 نبضة.
- `STOP` من المدير أو إغلاق قناة الإقلاع ينهي الـ shell بصفر (بعد الأمر الجاري إن كان ينتظر ردًّا).

## 3. المختبر (`tools/project.py`)

- الحالة التي تحمل `console: {port, after, script}` تُشغَّل بـ COM2 على `tcp:127.0.0.1:<port>`؛ `ConsoleSession` يتصل فور بدء QEMU، ينتظر المحثّ الأول، ثم علامة `after` في السجل التسلسلي (جاهزية الخدمات كلها)، ثم يرسل كل خطوة ويجمع إخراجها حتى المحثّ التالي. الحكم بعد خروج الضيف: `expect` (نصوص لازمة)، `absent` (ممنوعة)، `prompt` (المحثّ بعد الأمر)، `expect_serial` (`[prefix, serial_marker, terminator]`: القيمة التي تلي العلامة في السجل التسلسلي يجب أن تظهر خلف `prefix` في الإخراج — مقارنة ما يطبعه الـ shell بما طبعته النواة)؛ الخطوة `final` تنهي الجلسة. النص الكامل دليل (`console.log`) وكل إخفاق يُسمّى بخطوته في `missing`.
- `tests/test_console_session.py` (TST-M4-SHELL-TOOL، مضيف): الجلسة ضد shell زائف عبر TCP بالبروتوكول نفسه — التقسيم عند المحثّ، الانتظار على العلامة، أنواع التوقعات الأربعة، وتبليغ الإخفاقات بخطواتها.

## 4. الاختبارات الحاكمة

TST-M4-SHELL-SVC (`svc` يُظهر auth/net/sh `ready` من المدير؛ `cpu`/`mem` تطابق `cpus` و`frames_total` اللذين طبعتهما النواة في السطر `|ktest|shell_svc|cpus=…|frames_total=…`؛ `net dhcp` ثم `net` يُظهر `configured=1 ip=10.0.2.15`؛ `ls /SYSTEM`، `ls /`، `cat /DIR/INNER.TXT`، أخطاء `NOT_FOUND`/`NOT_DIR`/`UNKNOWN_COMMAND`؛ `exit` → `sh stopped` بصفر ولا بقايا ولا تسرب إطارات)، TST-M4-SHELL-LOGIN (بلا جلسة `not logged in` و`ERR NO_SESSION`؛ كلمة مرور خاطئة `login failed: ERR ACCESS`؛ `user` يدخل لكن `net policy` تُرفض `ERR ACCESS` من الخدمة؛ `admin` يدخل والأمر ينجح `OK` ثم يُعاد؛ المحثّ يعكس الجلسة؛ `logout` يعيد `nawah> ` و`ERR NO_SESSION`)، TST-M4-SHELL-TOOL (المضيف).
