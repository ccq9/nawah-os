# عقد النص — الإصدار 1 (WP-35، ADR-0019 §6)

قيد WP-35 — مسودة حتى إغلاقه بدليل CI؛ عند الإغلاق يُجمَّد: أي تغيير في الواجهة أو الخوارزميات أو البيانات = إصدار جديد مع سجل قرار. الكود: `user/libnawah-text` (الحزمة `nawah-text`: `no_std`، بلا تخصيص، بلا تبعيات، `#![deny(unsafe_code)]`)، `tools/unicode_tables.py` (توليد الجداول)، `tools/text_vectors.py` (عيّنة الضيف)، `user/apps/textprobe` (الضيف)، `tests/test_text.py` (المضيف).

## 1. البيانات والخطوط

- **قاعدة بيانات يونيكود 17.0.0** (مصدر رسمي، S72): `DerivedBidiClass.txt` (بما فيها قيم `@missing` الافتراضية: نقاط غير مُسندة في كتل اليمين-إلى-اليسار تأخذ R/AL)، `DerivedJoiningType.txt`، `BidiBrackets.txt`، و`BidiCharacterTest.txt` (مضغوطًا xz) تحت `user/libnawah-text/ucd/`. `tools/unicode_tables.py` يولّد منها `src/tables.rs` (1267 مدى للفئات، 529 مدى للربط، 128 زوج أقواس)؛ اختبار يتحقق أن الملف المولَّد حالي.
- **الخطوط** (S73): Noto Sans Regular وNoto Sans Arabic Regular (غير مُلمَّحة، TrueType/glyf) من مستودع googlefonts/noto-fonts عند الإيداع `ffebf8c1ee449e544955a7e813c54f9b73848eac`، بترخيص SIL OFL 1.1 (`OFL.txt` معها)، تحت `platform/assets/fonts/`؛ على قرص النظام `/SYSTEM/FONTS/NOTOSANS.TTF` و`NOTOARAB.TTF` و`OFL.TXT`. لا خط آخر.

## 2. الواجهة

- `font::Font::parse(&[u8]) -> Option<Font>`: الجداول `head` `maxp` `hhea` `hmtx` `cmap` (صيغ 4 و12؛ منصة 3/1، 3/10، 0/x) `loca` `glyf` (بسيطة ومركّبة بمصفوفات 2.14 حتى 4 مستويات) و`GSUB`/`GDEF` اختياريان. كل قراءة محدودة؛ الجدول المشوَّه = «غائب» لا ذعر. `glyph_id(cp)` (0 للغائب)، `advance(gid)`، `left_side_bearing(gid)`، `outline(gid, &mut Outline)` (حتى 1024 نقطة و64 مسارًا)، ومن GSUB: `feature_lookups(script, feature)`، `substitute_single` (النوع 1)، `substitute_ligature` (النوع 4)، `chain_context` (النوع 6 صيغة 3)، والامتداد (النوع 7).
- `bidi::Bidi::resolve(text, Base::{Ltr,Rtl,Auto}, levels) -> para_level` و`bidi::reorder(levels, order)`: UAX #9 — P2–P3، X1–X10 (تضمين وتجاوز وعزل، عمق 125)، W1–W7، N0 (أزواج الأقواس BD16، 63 مستوى)، N1–N2، I1–I2، L1، L2؛ حتى 1024 حرفًا للفقرة. الحرف المُزال بـ X9 مستواه `REMOVED` ولا يظهر في الترتيب. P1 (تقسيم الفقرات) وL3–L4 مسؤولية المستدعي.
- `shape::forms` و`shape::shape(font, text, glyphs, clusters)`: أشكال الربط من أنواع الربط (R، L، D، C، T؛ الشفاف يُتخطّى)، ثم ميزات GSUB للكتابة العربية بترتيب OpenType: `isol`، `fina`، `medi`، `init` (كلٌّ على حروف شكله، بأنواع البحث 1 و6/3 مع تخطي العلامات بأعلام البحث وفئات GDEF)، ثم `rlig` (لام-ألف).
- `raster::Rasterizer::render(outline, units_per_em, px, &mut Bitmap)`: تكبير إلى 26.6 بالتقريب للأسفل، تسطيح المنحنيات التربيعية بتسامح 1/64 بكسل، 4×4 عيّنات لكل بكسل في (i+½)/4، قاعدة non-zero، الحواف نصف مفتوحة في y؛ التغطية 0..16. `Bitmap::hash()` (FNV-1a 64، S70) لمقارنة المضيف بالضيف.
- `layout::Layout::line(fonts, text, base, px, glyphs) -> (n, width)`: المستويات، runs بمستوى واحد وخط واحد (حروف الكتابة العربية → الخط العربي، الباقي → اللاتيني، والغائب من الآخر)، تشكيل كل run عربي، عكس الأقواس المزدوجة في runs اليمين-إلى-اليسار، الترتيب البصري، والتقدم من `hmtx` (26.6). `render_line(...)` يرسم السطر على صندوق `0xRRGGBB`: الخلفية، ثم النص بخط الأساس عند 3/4 الارتفاع، على بعد 8 بكسلات من اليسار للفقرة اليسارية ومن اليمين لليمينية؛ مزج التغطية c لكل قناة `(قديم·(16−c) + لون·c + 8)/16`. `rgb_hash` هو تجزئة النافذة في display.md §ب.

## 3. الحدود المعلنة

لا hinting؛ لا GPOS (لا kerning ولا وضع العلامات: العلامة تُرسم بتقدمها في الخط)؛ لا CFF/OTF؛ لا سياقية GSUB بصيغتيها 1 و2 ولا النوع 5؛ العكس (L4) للأقواس المزدوجة فقط (BidiBrackets)؛ لا تقطيع أسطر ولا IME؛ الأرقام كما كُتبت (لا استبدال أرقام).

## 4. الاختبارات الحاكمة

- TST-M5-BIDI (مضيف): كل أسطر BidiCharacterTest-17.0.0 ‏(91,707) تطابق؛ الجداول حالية.
- TST-M5-GLYPHS (مضيف): القارئ = fontTools (S74) على الخطين في cmap والمقاييس والمخططات؛ المُنقِّط مقابل مرجع مستقل بالقاعدة نفسها: لا بكسل ممتلئ مقابل فارغ، فرق ≤ 4/16 على الحواف، الحبر ضمن 1%.
- TST-M5-SHAPING (مضيف): أرقام الأشكال = HarfBuzz ‏(S75) على 4,326 حالة؛ الأشكال حول ZWJ/ZWNJ؛ أنواع الربط؛ 6 أسطر مختلطة الاتجاه محسوبة يدويًا.
- TST-M5-TEXT-GUEST (ضيف): `textprobe` يقرأ الخطوط من `/SYSTEM/FONTS` ويعيد العيّنة (101 سطر bidi، 40 كلمة، 8 تجزئات) ويرسم سطرًا مختلطًا؛ لقطة الشاشة وعرض المضيف للسطر نفسه يطابقان تجزئة الضيف.
