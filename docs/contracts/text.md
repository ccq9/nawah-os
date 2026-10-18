# عقد النص — الإصدار 0 (مسودة M5، ADR-0019 §6)

مسودة تخطيط: تُجمَّد كإصدار 1 عند إغلاق WP-35 بدليل CI؛ ما لم يُنفَّذ منها لا يُعدّ مدعومًا.

- **المكتبة** `libnawah-text` (no_std، بلا تبعيات): `Font::parse(&[u8])` (OpenType: `cmap` صيغ 4 و12، `glyf`/`loca`، `hmtx`/`hhea`، `head` (unitsPerEm)، `GSUB` للأشكال العربية `init/medi/fina/isol` و`rlig` إن وُجد)، `rasterize(glyph, px) -> Bitmap` (مسح خطوط، non-zero winding، تنعيم 4×4)، `bidi(text) -> (levels, order)` (UAX #9: الأنواع من جدول مُضمَّن للنطاقات اللازمة، P2/P3، W1–W7، N1–N2، I1–I2، L1–L2)، `shape_arabic(text) -> forms` (الفئات الموصولة من ArabicShaping.txt مُضمَّنة؛ لام-ألف)، و`layout(text, font, px) -> [positioned glyphs]` يجمعها (تقسيم إلى runs حسب المستوى، تشكيل، قياس التقدم من hmtx).
- **الخطوط**: Noto Sans وNoto Sans Arabic (SIL OFL 1.1) تحت `/SYSTEM/FONTS/` مع `OFL.TXT`؛ مُسجَّلان مصدرين بتاريخ الوصول والإصدار؛ لا خط آخر.
- **الحدود المعلنة**: لا hinting، لا GPOS (kerning/marks)، لا خطوط CFF، الأرقام بصيغتها الغربية والعربية الهندية حسب الإعداد، لا IME.
- **الاختبارات الحاكمة**: TST-M5-BIDI (متجهات BidiCharacterTest المنشورة ضمن النطاق المدعوم)، TST-M5-SHAPING (متجهات مشتقة من ArabicShaping.txt)، TST-M5-GLYPHS (صور ذهبية من المضيف لمخططات الخط نفسها) — على المضيف وفي الضيف.
