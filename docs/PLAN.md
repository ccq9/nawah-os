# PLAN — خطة تنفيذ إصدار الحاسوب الأول (R1) وما بعده

الإصدار: 1 (2026-10-18). الحاكم: OS-EXEC-AR 3.2. هذه الخطة تفصّل المراحل M1–M9 إلى حزم عمل بمعايير قبول ومصادر رسمية؛ الحزم في docs/work-items.json هي السجل الملزم، وهذا الملف شرحها. كل رقم زمني غائب عمدًا: التقدير يُسجل بعد قياس أول حزمتين من كل مرحلة.

## 0. المبادئ التي تحكم كل حزمة

1. لا كود بلا اختبار يحكم عليه (ضيف أو مضيف)، ولا PASS بلا دليل في evidence/ مع بصمات المدخلات.
2. التصميم قبل التنفيذ: عقد في docs/contracts/ لكل مكوّن قبل أول سطر فيه.
3. المصدر الأولي قبل الذاكرة: كل حقيقة عتادية تُسند إلى Intel SDM / UEFI 2.11 / ACPI 6.5 / virtio 1.3 بالقسم.
4. الطبقات: arch (x86_64 فقط) ← core (منطق مشترك) ← platform (QEMU/PC) ← drivers. لا يعتمد core على x86_64 ضمنيًا.
5. كل حزمة تُغلق بـcommit واحد + checkpoint + CI أخضر.

## 1. سلسلة الأدوات والبناء (ADR-0002)

- Rust 1.97.0، x86_64-unknown-uefi، zero dependencies، lld-link عبر rustc. الحزمة kernel/ تنتج NAWAH.EFI (النواة العادية) وNAWAH-KTEST.EFI (نواة الاختبار بميزة ktest) وNAWAH-NEG.EFI (حقن فشل EBS).
- الواجهة tools/project.py تبقى (build/boot/test/validate-records/checkpoint/next/report)؛ build يستدعي cargo.
- CI: .github/workflows/verify.yml يثبّت الهدف بـrustup ويبني ويشغّل QEMU ويرفع evidence.
- المحلي: بعد وصول rust-std للهدف من المستخدم (بصمة متوقعة في ADR-0002) يُثبّت بـinstall.sh داخل toolchain stable، ويُسجل في ENVIRONMENT.md.

## 2. M1 (إعادة بـRust) — WP-06

- النطاق: port للستب والنواة الكعب: GetMemoryMap/EBS مع إعادة محاولة واحدة (UEFI 2.11 §7.4.6: EFI_INVALID_PARAMETER عند MapKey خاطئ؛ لا يُستدعى بعد أول EBS إلا خدمات تخصيص الذاكرة)، boot_info v1، أثر OSX|…|kernel|post_ebs، حقن الفشل، الفحص الساكن NOBS (الوحدة kmain لا تصل إلى boot::efi).
- القبول: TST-M1-BUILD/BOOT/NEG/NOBS PASS بأدلة جديدة؛ بوابة M1 تُعاد.
- الاختبار الذاتي الإضافي من Sol: فحص IDT عبر sidt (يُدمج في M2).

## 3. M2 — أساس النواة (WP-07 … WP-12)

| حزمة | المحتوى | مرجع الحكم | المصدر |
|---|---|---|---|
| WP-07 جداول المعالج والاستثناءات | GDT/TSS/IDT، مدخل لكل الاستثناءات الـ32، IST للخطأ المزدوج، حدّ تداخل، #BP يعود، طباعة إطار كامل. مكدس نواة ومكدس طوارئ مملوكان. | ktest: de, ud, bp, bp_state, gp, pf, df, nested, idt_layout؛ كل اختبار إقلاع مستقل برمز خروج | SDM Vol.3A §6.2.1, §7.10–7.15, Table 7-1, Fig 7-8/7-11, §10 (TSS) |
| WP-08 مدير الذاكرة الفيزيائية | مخصص إطارات بخريطة بتات من خريطة UEFI (الأنواع القابلة للاستعمال فقط؛ حجز صورة النواة وboot_info والجداول)، إحصاءات، فشل تخصيص يعيد None لا panic، كشف تحرير مزدوج | ktest: pmm_counts, pmm_exhaust, pmm_double_free | UEFI 2.11 §7.2 (أنواع الذاكرة، EfiConventionalMemory)، boot.md |
| WP-09 الذاكرة الافتراضية | جداول صفحات جديدة (PML4)، خريطة مباشرة للذاكرة الفيزيائية في النصف الأعلى، النواة بأذونات: .text RX، .rdata R، .data RW+NX، صفحات حراسة للمكدسات، CR0.WP، EFER.NXE، تبديل CR3 | ktest: vmm_switch, vmm_wp (كتابة على .text → #PF برمز 3)، vmm_nx (تنفيذ من .data → #PF)، vmm_guard (تجاوز المكدس → #DF على IST) | SDM Vol.3A §4.5 (4-level paging)، §4.6 (access rights)، §2.5 (CR0.WP)، Vol.4 (IA32_EFER.NXE) |
| WP-10 المقاطعات والمؤقتات | تقنيع 8259 PIC، LAPIC (xAPIC MMIO/x2APIC حسب CPUID)، I/O APIC من ACPI MADT، مؤقت LAPIC بمعايرة PIT أو ACPI PM timer، مؤقت دوري، IRQ 32+، EOI، تأكيد عدم إعادة الدخول | ktest: timer_ticks (≥N نبضة خلال مهلة)، irq_eoi، spurious | SDM Vol.3A §11 (APIC)، ACPI 6.5 §5.2.12 (MADT)، §5.2.9 (FADT PM timer)؛ 8259/8254 (Intel datasheets الموثقة) |
| WP-11 التزامن الأولي وسياسة panic | IRQ-save spinlock لمعالج واحد، كاتب تسلسلي بقفل، panic يطبع ويتوقف برمز، سياسة نفاد الموارد | ktest: lock_irqsave, panic_code | Sol ADR-007 (مرجع)، SDM §9 (ترتيب الذاكرة) |
| WP-12 بوابة M2 | جناح M2 كامل، اختبار طفرات، مراجعة ذاتية مسماة، تحديث ENVIRONMENT/PLAN | كل ما سبق + mutants ≥ 95% مكشوف | — |

## 4. M3 — العمليات والموارد والواجهات (WP-13 … WP-22)

ترتيب الحزم مقصود: ما لا يجمّد عقدًا مشتركًا أولًا (الكومة وunmap)، ثم تجربة النقل المبكرة إلى AArch64 **قبل** تجميد ABI النداءات (البند 8 من البرومبت)، ثم وضع المستخدم وABI، ثم العمليات والجدولة، المقابض وIPC، المحمّل، التخزين، VFS، SMP، وأخيرًا بوابة M3. كل حزمة لها اختبار يحكمها قبل تفعيلها؛ ما يتجاوز الميزانية يُقسَّم.

| الحزمة | المحتوى | الاختبار الحاكم | المصادر |
|---|---|---|---|
| WP-13 كومة النواة وunmap | `GlobalAlloc` فوق PMM والخريطة المباشرة (مخصص كتل بسيط)، `unmap/protect` مع `invlpg`، كائن فضاء عناوين مستخدم (PML4 جديد يشارك النصف الأعلى)، إطار إبطال TLB لمعالج واحد | ktest: heap_stress (تخصيص/تحرير 10k كتل بأنماط، لا تسريب في عدّاد PMM)، vmm_unmap (الوصول بعد unmap → #PF)، as_switch (تبديل فضاء مستخدم فارغ والعودة) | SDM Vol.3A §4.10 (TLB، invlpg) (S26) |
| WP-21 تجربة النقل المبكرة (AArch64، حزمتان كحد أقصى) | بناء `aarch64-unknown-uefi`، إقلاع على QEMU virt (EDK2 AAVMF)، ExitBootServices، أثر تسلسلي PL011، فصل arch/aarch64 عن المشترك؛ **لا** يُعلَن دعم المحمول | build + boot على هدف `virt-qemu-aarch64` بأوراكل مماثل لـ TST-M1-BOOT | UEFI 2.11 §2.3.6 (AArch64 calling convention/entry)، QEMU virt، Arm ARM (PL011) |
| WP-14 وضع المستخدم وABI النداءات | مقاطع GDT للمستخدم (ترتيب sysret)، TSS.RSP0، `syscall/sysret` (EFER.SCE، STAR/LSTAR/FMASK)، swapgs ومنطقة per-CPU (GS)، جدول نداءات برقم ثابت ورموز أخطاء، التحقق من مؤشرات/أطوال المستخدم (copy_in/out)، SMEP/SMAP إن توفرا؛ عقد `docs/contracts/syscall.md` مجمَّد بإصدار | ktest: user_syscall (كود حلقة 3 مضمَّن يستدعي نداءً ويستلم قيمة)، user_bad_ptr (مؤشر غير صالح → خطأ لا panic)، user_kernel_access (قراءة عنوان النواة من حلقة 3 → إنهاء العملية بتشخيص)، sysret_canonical | SDM Vol.3A §5.8.8 (SYSCALL/SYSRET)، §2.5 (SMEP/SMAP)، Vol.4 (STAR/LSTAR/FMASK/KERNEL_GS_BASE) (S26) |
| WP-15 الخيوط والعمليات والجدولة | TCB/PCB، تبديل سياق (sysv64 callee-saved)، طابور تشغيل بأولويات ثابتة + round-robin، استباق بالمؤقت، sleep/yield/exit، تحرير فضاء العناوين والإطارات عند الخروج | ktest: threads_alternate، preempt_no_starvation (خيط دوّار لا يجوّع آخر)، exit_cleanup (free_frames قبل = بعد) | SDM §6 (task state)، Sol ADR-007 (نموذج الجدولة) |
| WP-16 المقابض والقدرات وIPC | جدول مقابض لكل عملية بحقوق، أنواع كائنات (process/thread/channel/vmo)، قنوات رسائل بحد حجم (4 KiB) وتمرير مقابض، فحص الحقوق في كل نداء | ktest: ipc_roundtrip، rights_denied، closed_handle، oversize_rejected، no_leak_after_exit | Sol ADR-006 (نموذج القدرات)، Fuchsia handle/rights model كمرجع تصميمي (لا شيفرة) |
| WP-17 محمّل ELF64 ووقت تشغيل أدنى | PT_LOAD بأذونات W^X، مكدس المستخدم، نقطة الدخول؛ `libnawah` (أغلفة النداءات) وتطبيقات اختبار صغيرة تُبنى بنفس سلسلة الأدوات (x86_64-unknown-none) | ktest/guest: app_exit_code، malformed_elf_rejected، wx_rejected | ELF-64 (gABI/System V)، SDM NX |
| WP-18 التخزين | تعداد PCI (ECAM من ACPI MCFG)، virtio-blk 1.x (PCI capabilities, split virtqueue)، طبقة كتل بطابور طلبات وflush، نظام ملفات أول (FAT32 على صورة قرص ثانية للتوافق مع ESP + نظام داخلي بسيط لاحقًا)، اختبار ثبات عبر إعادة تشغيل QEMU | guest: blk_read_pattern، blk_write_flush_reboot_read (تشغيلان متتاليان على الصورة نفسها) | Virtio 1.3 §4.1 PCI، §5.2 block device؛ PCI Firmware Spec (MCFG)؛ Microsoft FAT32 spec |
| WP-19 VFS والملفات | open/read/write/close/stat عبر النداءات، حل المسارات، جدول ملفات لكل عملية، حقوق | guest apps: file_roundtrip، path_invalid، fd_leak_check | — |
| WP-20 SMP | تشغيل APs (INIT-SIPI-SIPI، trampoline < 1 MiB)، بنى per-CPU (GS)، IDT مشترك وGDT/TSS لكل معالج، مؤقت LAPIC لكل معالج، **تثبيت الخيوط على معالجها** بدل طوابير per-CPU (ADR-0015 §5؛ الطوابير والهجرة قرار لاحق)، IPIs لإبطال TLB وإعادة الجدولة، `cpu_id` حقيقي، اختبار تنازع أقفال؛ ثم كل الأجنحة بـ`-smp 4` | ktest (-smp 4): smp_online == MADT، lock_contention 400000 بالضبط، tlb_shootdown | SDM Vol.3A §9.4 (MP initialization؛ §8.4 في الطبعات الأقدم)، §11.6 (IPI)، §4.10.5 (TLB)، ACPI MADT (S33) |
| WP-22 بوابة M3 | أجنحة العزل والموارد والثبات كاملة (ISOLATION، PRIORITY-ORDER أُضيفا)، اختبار الطفرات على وحدات M3 (M30–M49: 20/20 بعد تدقيق المكافئات وأعطال المختبر)، مراجعة مسماة docs/operations/m3-review.md، تحديث PLAN/ENVIRONMENT — **مرّت 2026-10-18** (CI run 39123846027 وجولة الطفرات 39123845703) | البند 20 M3 | — |

- القبول: البند 20 M3 في البرومبت: عملية سليمة تعمل؛ تُرفض المؤشرات/الأطوال/الحقوق غير الصالحة؛ لا تصل عملية إلى ذاكرة أخرى أو النواة؛ تُنظَّف الموارد بعد الإنهاء؛ البيانات المقر حفظها تبقى بعد إعادة التشغيل؛ السباقات وSMP عند دخولهما النطاق.
- قيود: البناء على CI فقط حتى توفر مكوّن rust-std المحلي؛ تطبيقات المستخدم تحتاج هدف `x86_64-unknown-none` (يُثبَّت على CI).

## 5. M4 — الخدمات (WP-23 … WP-31)

النموذج في ADR-0016: الخدمة عملية مستخدم تُحمَّل من حجم النظام وتتخاطب بالقنوات؛ السلطة مقدرة (مقبض رمز جلسة) تُفحص في الخدمة لا في الواجهة؛ مدير خدمات `svcmgr` أول عملية. virtio-gpu/virtio-input يُنقلان إلى M5 حيث اختباراتهما (الإطار والإدخال). الصوت والوسائط خارج نطاق R1 المعتمد.

| الحزمة | المحتوى | الاختبار الحاكم | المصادر |
|---|---|---|---|
| WP-23 ABI v1.4 | `process_spawn` من الحجم بمقابض أولية وكائن عملية، `object_wait_many` بمهلة (حتى 64 مدخلًا)، `clock_ticks`، `process_status`، مقبض الإقلاع في rdi؛ التطبيقات على الصورة تحت `/SYSTEM` — **أُغلق 2026-10-18** (CI run 39130028974؛ 7 جولات كشفت: تخطيط RELRO في ربط التطبيقات، مدى صفري عند حافة المستخدم، ترتيب فحص النوع/الحقوق) | TST-M4-SPAWN-VOLUME، WAIT-TIMEOUT، CHILD-EXIT | عقود M3، SysV ABI (S37) |
| WP-24 svcmgr | البيان، الترتيب الطوبولوجي، مهلة الجاهزية، إعادة تشغيل بحد وتراجع، قناة تحكم؛ النواة تبدؤه أول عملية (`kernel|svcmgr|…|reply=OK 0`) — **أُغلق 2026-10-18** (CI run 39130028974) | TST-M4-SVC-ORDER، SVC-TIMEOUT، SVC-RESTART، TST-M1-BOOT | §8.7 |
| WP-25 المصادقة | SHA-256/HMAC/PBKDF2 بمتجهات (FIPS 180-4، RFC 4231، RFC 6070)، كائنا Token/Authority، خدمة auth، حد محاولات، قفل/خروج — **أُغلق 2026-10-18** (CI run 39133153681: متجهات FIPS/RFC على المضيف وفي الضيف، رموز بهوية، دخول/قفل/خروج، حد محاولات) | TST-M4-HASH-VECTORS، LOGIN، SESSION-LOCK، AUTHZ-DENIED | FIPS 180-4، RFC 2104، RFC 8018، NIST SP 800-132 |
| WP-26 التكوين | مخازن device/user/session/policy بإصدارات، CAS، request_id، إشعارات، أسبقية، حفظ آمن — **أُغلق 2026-10-18** (CI run 39133153681: CAS وتكرار وإشعارات وأسبقية وثبات بخانتين، السلطة في الخدمة) | TST-M4-CONFIG-PERSIST، CAS، RETRY، NOTIFY، POLICY-PRECEDENCE | §12–13 |
| WP-27 التعريفات | virtio-net، PS/2 (i8042)، حدود موارد، نموذج ثقة DMA — **أُغلق 2026-10-18** (CI run 39134727743: virtio-net بحدود ثابتة ونموذج DMA، ARP للبوابة، i8042 بالاستطلاع، كائنا Nic/Keyboard، ABI v1.6) | TST-M4-NET-LINK، NET-LIMITS، KBD-SCANCODES | Virtio 1.3 §5.1 (S42)، i8042/PS2 |
| WP-28 الشبكة | ARP/IPv4/ICMP/UDP/DHCP، فصل الإنترنت، سياسة لا إنترنت — **أُغلق 2026-10-18** (CI run 39137446701: DHCP من SLIRP، صدى ICMP موقوت، صدى UDP عبر نظير المضيف، فصل link/configured/internet بسياسة لا إنترنت؛ جولتان كشفتا سعة متجه المنتظرين في كائنات النواة الدائمة) | TST-M4-DHCP، ICMP-ECHO، UDP-ECHO، NET-NO-INTERNET | RFC 826/791/792/768/2131/2132 (S53–S60) |
| WP-29 TCP | مصافحة، بيانات، إغلاق، RTO، مقابس — **أُغلق 2026-10-18** (CI run 39139475715: عميل stop-and-wait بمصافحة وإغلاق منظم وRST، مؤقت RFC 6298 بتراجع أسي وKarn مُثبَت بحقن إسقاط مقطع؛ جولتان: الثانية صحّحت عدّ بايتات في الوحي فقط) | TST-M4-TCP-ECHO، TCP-RETRANSMIT | RFC 9293 (S61)، RFC 6298 (S62) |
| WP-30 الـ shell | shell تشخيصي على COM2 بمقبس مختبر: كائن قناة التشخيص وABI v1.7 (serial_read/write، system_info، dir_list)، الخدمة `sh` تجيب من مالك كل حالة، جلسة المختبر `ConsoleSession` — **أُغلق 2026-10-18** (CI run 39141804574؛ ثلاث جولات: بوابة cfg لـ aarch64، ثم مقبض الرمز يُنقل لا يُنسخ فصار يُرسَل نسخةً) | TST-M4-SHELL-SVC، SHELL-LOGIN، SHELL-TOOL، TST-M1-BOOT | 16550 (S63)، QEMU -serial (S64) |
| WP-31 البوابة | انقطاع الطرف (عميل يختفي، خدمة تموت وتُعاد)، سلطة ما بين الخدمات (CONNECT للتبعيات المعلنة؛ السكّ بالسلطة وحدها؛ إبطال الرمز عند LOGOUT)، طفرات M4 (M50–M81: 32/32)، مراجعة مسماة docs/operations/m4-review.md، تحديث PLAN/ENVIRONMENT/threat-model — **مرّت 2026-10-18** (CI run 39144177809 وجولة الطفرات 39144910448؛ ثلاث جولات: حجز جداول المجدول ثم خط أساس ELF-MALFORMED) | TST-M4-PEER-LOSS، TST-M4-MUTANTS | البند 20 M4 |

- القبول: البند 20 M4: ترفض الخدمة الطلب غير المخول عند طبقة السلطة؛ تحفظ الحالة كما وعدت؛ تتعافى من انقطاع طرف أو فشل خدمة وفق العقد؛ ترتيب البدء والمهلات وتكرار الطلب والتحديث المتزامن وحدود موارد التعريفات مختبرة؛ شرط DMA مثبَّت قبل التمكين.

## 6. M5–M7 — الرسوم والواجهة والإعدادات

- M5: compositor + مدير نوافذ + إدخال موثوق + قفل جلسة مملوك لجهة موثوقة + نص عربي/إنجليزي (UAX #9 bidi، تشكيل عربي، خطوط مرخصة) + وصول (تنقل لوحة مفاتيح، قارئ شاشة واجهة). القرارات في ADR-0019؛ الحزم:

| الحزمة | المحتوى | الاختبار الحاكم | المصادر |
|---|---|---|---|
| WP-32 العرض | إطار GOP قبل EBS في BootInfo، رسم الإطار في النواة (WC) ونمط تشخيصي بالإقلاع، `Object::Display` وABI v1.8 (`display_info`، `display_map`، وخرائط المستخدم `vmo_map`/`vmo_unmap`)، مجس الشاشة في المختبر (`screendump` + `tools/screen.py`) — **أُغلق 2026-10-18** (CI run 39151090992؛ ثلاث جولات: ترتيب خطوات البناء، ثم النوع قبل الحقوق في `vmo_map`) | TST-M5-DISPLAY-BOOT | UEFI 2.11 §12.9، QEMU monitor screendump |
| WP-33 الإدخال | منفذ i8042 المساعد وفأرة PS/2 (`Object::Mouse`)، خدمة `input`: رموز مفاتيح وتخطيطان (US، عربي)، توجيه إلى مالك التركيز الذي تسميه الجلسة، الانتباه الآمن | TST-M5-INPUT-ROUTE، MOUSE | i8042/PS2 (S54)، QEMU sendkey/mouse |
| WP-34 الـ compositor | خدمة `display`: أسطح VMO يملكها العميل، COMMIT بمناطق التغيير، مخزن خلفي بإيقاع النبضة، نوافذ بزخرفة وترتيب وتركيز وحجم، تطبيق لا يستجيب، `libnawah-display` وتطبيق `winapp` | TST-M5-WINDOW-STATES، APP-HANG، SCREEN | §9 |
| WP-35 النص | `libnawah-text`: OpenType (cmap/glyf/hmtx/GSUB)، تنقيط بمسح الخطوط، UAX #9، تشكيل عربي، خطا Noto (OFL) تحت `/SYSTEM/FONTS` | TST-M5-BIDI، SHAPING، GLYPHS (مضيف + ضيف) | UAX #9، ArabicShaping.txt، OpenType spec، OFL 1.1 |
| WP-36 الواجهة والوصول | `libui`: نافذة/زر/تسمية/حقل نص/قائمة/مربع اختيار/تمرير، شجرة تركيز بترتيب معلن، تنقل لوحة المفاتيح، إعلانات التركيز إلى `narrator`، تكبير وتباين من `config` | TST-M5-KEYBOARD-NAV، A11Y-TREE | §17 |
| WP-37 الجلسة والقفل | خدمة `session` تملك القفل والرمز وشاشة الدخول؛ إدخال المصادقة من `input` مباشرة؛ البقاء عند تعطل display/input؛ إنقاذ مصادَق عند تعطل الجلسة؛ البيان الحقيقي SERVICES.TXT | TST-M5-LOCK-SURVIVES، AUTH-INPUT-ISOLATED، LOGIN-SCREEN | §9، §12 |
| WP-38 بوابة M5 | سيناريوهات §20 (7، 8، 11)، طفرات M82+ ≥95%، مراجعة مسماة، تحديث PLAN/ENVIRONMENT/threat-model | TST-M5-MUTANTS | البند 20 M5 |

- القبول: البند 20 M5: تتعامل النوافذ مع الحجم والتركيز وتوقف تطبيق؛ تبقى الجلسة مغلقة عند تعطل مكونات العرض؛ لا يتسرب إدخال المصادقة إلى تطبيق؛ النص العربي والمختلط والتنقل بلوحة المفاتيح مفحوصة.
- قيود معلنة: لا تغيير لوضع الفيديو ولا تسريع؛ لا hinting ولا GPOS؛ قارئ الشاشة نصي على قناة التشخيص؛ الحافظة والسحب والإفلات في M6.
- M6: سطح مكتب، ابدأ، شريط مهام، إشعارات، مستكشف ملفات، أدوات إدارية بمقاييس حقيقية — السلوك من جرد المرجع (DEC-002).
- M7: إعدادات R1 (ثلاث صفحات على الأقل: العرض، الوقت واللغة، الحسابات) بعقد البند 12 لكل إعداد.

## 7. M8–M9 — SDK والتوافق والتثبيت والتحديث

SDK أصلي + أمثلة؛ مثبّت على قرص افتراضي فارغ؛ تحديث موقّع (TUF كمرجع نموذج تهديد)؛ A/B أو snapshots بقرار معماري؛ نسخ احتياطي واستعادة مختبرة في بيئة نظيفة.

## 8. المحمول (M12–M15)

يبدأ بعد قبول R1. الافتراض المقترح للقرار: لوحة ARM64 بلا مودم (تُحسم في M12). لا دعم يُعلن قبل التنفيذ.

## 9. المخاطر الحاكمة للخطة

RSK-001 (اتساع النطاق) وRSK-003 (الشبكة) وRSK-006 (وكيل واحد) في docs/risks.json. إشارة الإنذار الأولى: أي حزمة تتجاوز ميزانيتها (120 استدعاء أداة) دون اختبار ناجح تُقسَّم.
