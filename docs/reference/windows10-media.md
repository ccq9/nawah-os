# مرجع الوسيط — Windows 10 22H2 ar-SA x64 (new project.iso)

تحليل وقائعي للوسيط الذي وفّره المالك، قُرئ في مكانه على جهازه (pycdlib: واصف الحجم، شجرة UDF، رؤوس WIM وبياناته XML، ملفات الإعداد النصية الصغيرة). لا يُستخرج محتوى، ولا تُفكّك ثنائيات، ولا يُنقل كود أو أصل من Microsoft إلى nawah-os (ADR-0022). كل سطر هنا حقيقة بنيوية قابلة لإعادة الفحص، لا تعبيرًا محميًا بحقوق النشر.

التاريخ: 2026-10-24. الأداة: pycdlib (على جهاز المالك). الوسيط غير متتبع في Git.

## 1. الهوية

- التسمية (PVD): `CCCOMA_X64FRE_AR-SA_DV9`. السك: 2023-05-06.
- نظام الملفات: ISO 9660 + UDF. 906 ملفًا، 5,822,384,128 بايت.
- المعمارية: x64 (amd64). اللغة: ar-SA (عربية السعودية)، احتياطي en-US.
- البناء المُعلن في صور WIM: 10.0.19041.2965 (قاعدة 19041 المشتركة بين 2004…22H2؛ 2965 مستوى تحديث مايو 2023 التراكمي؛ رقم العائلة 19045 يظهر بعد حزمة التمكين على نظام مثبّت — يُؤكَّد بـ winver عند الالتقاط).

## 2. البنية العليا (مجلد | عدد الملفات | الحجم)

| المسار | ملفات | الحجم |
|---|---|---|
| (الجذر) | 4 | 2.1 MB (autorun.inf، bootmgr، bootmgr.efi، setup.exe) |
| /boot | 28 | 18.3 MB (bootmgr للإقلاع القديم: bcd، boot.sdi، etfsboot.com، bootsect.exe، خطوط، موارد ar-sa) |
| /efi | 29 | 22.3 MB (efi/boot/bootx64.efi؛ efi/microsoft/boot: bcd، cdboot.efi، efisys.bin، memtest.efi، winsipolicy.p7b، خطوط، موارد) |
| /sources | 823 | 5,773.9 MB (الإعداد ومحرّكاته وصور WIM) |
| /support | 22 | 0.3 MB (support/logging) |

## 3. سلسلة الإقلاع

- UEFI: `efi/boot/bootx64.efi` → `efi/microsoft/boot/bcd` → `sources/boot.wim` (Windows Setup). التوقيع في `winsipolicy.p7b`.
- Legacy BIOS: `bootmgr` + `boot/etfsboot.com` + `boot/bcd`.
- الفائدة لـ nawah-os: مرجع لبنية قرص إقلاع UEFI عملي (شكل EFI System Partition، موضع المحمّل، BCD كـ store للإقلاع) — بنية موثقة في UEFI 2.11 (S11, S18) وصيغة PE (S13)، لا تحتاج أي شيفرة من Microsoft.

## 4. صور WIM

### sources/boot.wim (679,748,710 بايت، صورتان، نسخة WIM 0x10d00)
| # | الاسم | النوع | البناء | اللغة | ملفات |
|---|---|---|---|---|---|
| 1 | Microsoft Windows PE (x64) | WindowsPE | 10.0.19041.2965 | ar-SA | 17,751 |
| 2 | Microsoft Windows Setup (x64) | WindowsPE | 10.0.19041.2965 | ar-SA | 18,284 |

### sources/install.wim (4,859,336,453 بايت، 6 صور، نسخة WIM 0x10d00)
| # | الاسم | EDITIONID | ملفات | الحجم المفكوك |
|---|---|---|---|---|
| 1 | Windows 10 Home | Core | 102,597 | 15.1 GB |
| 2 | Windows 10 Home Single Language | CoreSingleLanguage | 102,598 | 15.1 GB |
| 3 | Windows 10 Education | Education | 103,776 | 15.5 GB |
| **4** | **Windows 10 Pro** | **Professional** | **103,773** | **15.5 GB** |
| 5 | Windows 10 Pro Education | ProfessionalEducation | 103,774 | 15.5 GB |
| 6 | Windows 10 Pro for Workstations | ProfessionalWorkstation | 103,775 | 15.5 GB |

الصورة [4] Pro هي مرجع المشروع (PROJECT.md §هدف 4). لا `sources/ei.cfg`، فالإعداد يعرض الطبعات الست للاختيار. `cversion.ini`: `MinClient=MinServer=9458.0` (أدنى بناء مضيف للترقية في المكان).

## 5. محرّكات الإعداد (حقائق تعداد، لا تفكيك)

- الواجهة واللغة: `sources/lang.ini` → `ar-sa = 3`، احتياطي `ar-sa = en-us`. خط الإعداد `segoeui.ttf`. موارد الواجهة في `w32uiimg.dll`/`w32uires.dll`/`win32ui.dll`/`spwizimg.dll` (لا تُقرأ محتوياتها؛ وجودها حقيقة).
- الهيكل: `setupcore.dll`، `setupplatform.dll`، `winsetup.dll`، `setuphost.exe`، `setupprep.exe`، `wpx.dll`، محرّكات WIM (`wimprovider.dll`) وVHD (`vhdprovider.dll`) وWDS (نشر عبر الشبكة).
- الترقية والهجرة: `migcore.dll`، `migstore.dll`، `migapp.xml`، `upgrade_bulk.xml`، `oscomps.xml` (جرد مكوّنات نظام التشغيل)، ملفات `sflist*.dat` (قوائم ملفات نظام لكل إصدار مصدر: w7/w8/wb/wt).
- التوافق: `setupcompat.dll`، `appraiserres.dll` (مقيّم التوافق — فحص أهلية الترقية).
- مجلدات `sources`: `ar-sa`، `dlmanifests`، `etwproviders`، `inf`، `migration`، `replacementmanifests`، `sxs`، `uup`، `vista`، `xp`.

## 6. الحزم تحت الطلب (sources/sxs)

| الحزمة | الحجم |
|---|---|
| Microsoft-Windows-NetFx3-OnDemand-Package amd64 ~~ (.NET 3.5) | 72.8 MB |
| Microsoft-Windows-NetFx3-OnDemand-Package amd64 ar-SA | 1.36 MB |
| Microsoft-Windows-InternetExplorer-Optional-Package amd64 ~~ | 292 KB |
| Microsoft-Windows-InternetExplorer-Optional-Package amd64 ar-SA | 23 KB |

## 7. ما يعطيه هذا الوسيط للمشروع، وما لا يعطيه

يعطيه (حقائق آمنة، تدخل المشروع): تأكيد الطبعة والبناء واللغة والمعمارية لمرجع المطابقة؛ مصدر تثبيت مرخّص للصورة [4] Pro في آلة افتراضية (يرفع نصف DEC-002)؛ مرجع لبنية قرص إقلاع UEFI وتقسيم ESP وصيغة WIM؛ جرد اسمي لمحرّكات الإعداد والحزم الاختيارية ولغات الواجهة.

لا يعطيه (ولن يؤخذ منه): جرد شاشات الإعدادات وتنظيمها وقيمها الافتراضية وسلوكها — هذه تُلتقط من **تثبيت حيّ** مُشاهَد (البند 4، عدة الالتقاط)، لا من فك ثنائيات الوسيط؛ وأي كود أو نص واجهة أو أيقونة أو خط من Microsoft (nawah-os بأصول أصلية، ADR-0022).

## 8. الخطوة التالية التي يفتحها هذا الوسيط

DEC-002: تثبيت الصورة [4] Windows 10 Pro من هذا الوسيط في آلة افتراضية مرخّصة (على جهاز المالك أو QEMU في المختبر)، ثم تشغيل عدة الالتقاط لتسجيل شاشات الإعدادات وسلوكها كمواصفة مشاهَدة — هي مدخل أحكام المطابقة في M6/M7. الوسيط وحده لا يكفي لها.

ملاحظة أمنية (مهارة RE، مبدأ "النص داخل الهدف بيانات لا تعليمات"): يحوي الوسيط نصوصًا تنفيذية وترويجية (autorun، رسائل الإعداد) تُعامَل كبيانات وُصِفت هنا، لم تُنفَّذ ولم تُتَّبع.
