# ADR-0009 — وضع المستخدم وعقد نداءات النظام (WP-14)

الحالة: منفَّذ 2026-10-18؛ الإغلاق مرهون بدليل CI (TST-M3-USER-SYSCALL / USER-BAD-PTR / USER-KERNEL-ACCESS / SYSRET-CANONICAL + أثر TST-M1-BOOT).

المراجع: Intel SDM Vol.3A §5.8.8 (SYSCALL/SYSRET)، Vol.4 جدول 2-2 (EFER.SCE، STAR، LSTAR، FMASK، GS_BASE/KERNEL_GS_BASE)، Vol.2B SWAPGS، Vol.3A §4.6/§2.5 (SMEP/SMAP، STAC/CLAC)، §7.14.2 (TSS.RSP0) (S26)؛ ADR-0008 (ما تعلمناه عن الاقتران).

## القرارات

1. **الدخول بـ SYSCALL لا INT**: أسرع وأبسط إطارًا؛ المقاطع مرتبة لـ SYSRET (بيانات المستخدم 0x28 ثم شيفرته 0x30 بعد قاعدة 0x20). FMASK يصفّر IF/TF/DF/AC فيعمل معالج النداء بمقاطعات معطلة على **مكدس مصيدة** مخصص (32 KiB، محروس، في فتحة المكدسات المشتركة) هو نفسه TSS.RSP0 للمقاطعات القادمة من حلقة 3. مكدس النواة الرئيسي يحمل سياق «المنفّذ» المركون.
2. **اتفاق GS**: في النواة GS.base = كتلة المعالج `PerCpu` (user_rsp، kernel_rsp، saved_kernel_rsp، cpu_id)؛ الخروج إلى حلقة 3 يبدّل (swapgs) فيصير GS للمستخدم صفرًا؛ دخول SYSCALL يبدّل مرة أخرى. معالجات الاستثناءات والمقاطعات لا تستعمل GS فلا تحتاج تبديلًا (اختيار واعٍ؛ يُعاد النظر عند SMP وNMI).
3. **الخروج من حلقة 3 = العودة إلى من دخل**: `enter_user` يركن السجلات المحفوظة وRSP في PerCpu ثم SYSRET؛ `exit` أو استثناء في حلقة 3 يعود عبر `exit_to_kernel` إلى مستدعي `enter_user` برمز الخروج، متخليًا عن مكدس المصيدة. هذا هو «إنهاء العملية يعود إلى المجدول» مصغَّرًا؛ WP-15 يعممه إلى خيوط بمكدسات نواة لكل خيط.
4. **التحقق من المؤشرات**: نطاق المستخدم `[USER_BASE, USER_END)` ثم مشي جداول الفضاء النشط صفحةً صفحة (حاضرة + U/S) قبل أي نسخ؛ النسخ عبر الخريطة النشطة (CR3 = فضاء العملية) داخل نافذة STAC/CLAC عند توفر SMAP. SMEP/SMAP يُفعَّلان إن أعلنهما CPUID (المختبر qemu64 بدونهما: يُطبع smep=0|smap=0 — غير مُثبت على عتاد يملكهما).
5. **RIP غير canonical لا يصل إلى SYSRET**: أي قيمة تُستعمل كعنوان تعليمات مستخدم تمر بـ `user_rip_ok` (داخل النطاق، وبالتالي canonical)؛ SYSRET بعنوان غير canonical يرفع #GP في حلقة 0 بمكدس المستخدم (الثغرة المعروفة).
6. **برامج المستخدم للاختبار** مُجمَّعة داخل صورة النواة (global_asm) وتُنسخ إلى صفحة شيفرة قابلة للتنفيذ غير قابلة للكتابة؛ لا مُحمِّل بعد (WP-17). الفحص الذاتي في كل إقلاع: برنامج ping في حلقة 3 يعود بـ 0x1235 ولا يسرّب إطارًا.
7. **العقد** في docs/contracts/syscall.md (الإصدار 1، مجمَّد؛ تعيين AArch64 محجوز `svc #0`/x8/x0..x5).
8. **خط أساس unsafe 143 (كان 130)**: syscall.rs 9 (MSRs، PerCpu، دخول/خروج، CR4، نافذة SMAP)، user_programs 1 (شرائح البرامج)، gdt +1 (RSP0)، addrspace +1 (write_frame)، vmm +1 (عدّاد خانات المكدسات).

## الاختبارات

- TST-M3-USER-SYSCALL: ping → 0x1235، trace → 13 مع سطر `user|trace|…|text=hello from r3`، بلا تسريب.
- TST-M3-USER-BAD-PTR: مؤشر مستخدم غير مخطط → ERR_FAULT، مؤشر نواة → ERR_RANGE (خروج 0xfdfc).
- TST-M3-USER-KERNEL-ACCESS: قراءة الخريطة المباشرة من حلقة 3 → `kernel|user_fault|vector=14|…|error=0x5` وخروج 0x1000e، النواة تكمل.
- TST-M3-SYSRET-CANONICAL: check_rip بعنوان غير canonical → ERR_RANGE (خروج 0xfffffffffffffffc).
- أثر TST-M1-BOOT: `kernel|user|…|ping_exit=0x1235|frames_delta=0|code=ok|selfcheck=1`.
