# ADR-0026 — أصل الدليل وفحص الاستيراد (WP-65)

الحالة: مقبول (2026-11-09). الأصل: إجابة الفريق الأربعة عشري على الخطة (docs/PLAN-ANSWER.md §2.8 و§5.3 البنود 1 و2 و4)، بعد تدقيقها.

## السياق

- كل أحكام PASS المستوردة من CI حتى 2026-11-09 (149 حكمًا) تحمل `worker=interactive-agent` و`dirty_state=true` مع أنها أدلة مشغّل التحقق، لأن `write_run` لا تعرف أين تعمل، ولأن `dirty` كان يُحسب من كل الشجرة بما فيها `evidence/` التي يكتبها التشغيل نفسه.
- كان `import-ci-evidence` يستورد أي فرع `ci-evidence/<run>` بلا فحص نتيجة التشغيل، ويعدّل `notes` في `run.json` بعد إنتاجه. وقد قيس فعلًا أن لتشغيلَين ملغيَين (42623295604 و42623032466) فرعَي أدلة منشورين لأن النشر بشرط `if: always()`.
- البند 22.6 من البرومبت الحاكم يشترط تسجيل المنفذ والمراجع بهويتين مختلفتين؛ ولا تُبنى هوية على نص حر يُزوَّر.

## القرار

1. **evidence-run 1.1.0** (`docs/schemas/evidence-run.schema.json`): `worker` من تعداد مغلق `[verification-runner, interactive-agent, test]` يطابق `docs/automation.json`؛ كائن `ci` يكتبه المشغّل من بيئة GitHub Actions (run_id, run_attempt, workflow, event, sha, head_sha, ref)؛ و`dirty_paths` بأول خمسين مسارًا. الإصدار 1.0.0 يبقى صالحًا.
2. **الكاتب**: `write_run` يستنتج العامل من البيئة (`GITHUB_ACTIONS=true` تعني مشغّل التحقق)، ويحسب `dirty_state` على الملفات المتتبَّعة المعدّلة والملفات الجديدة خارج `evidence/` و`build/` و`state/` (REL-3 B)، ولا يُستعمل `dirty_state` حَكَمًا قبل قياس أول تشغيل CI.
3. **الاستيراد المفحوص** (REL-2 A): `import-ci-evidence` يسأل GitHub عبر `gh run view` ويرفض كل تشغيل ليس `completed/success`، أو ليس من `verify` أو `mutants`، أو رأسه ليس سلفًا لـHEAD، أو معرّفه لا يطابق `^(mutants-)?[0-9]+$`. غياب gh أو خطأه يعطي `E_BLOCKED` بلا نسخ. لا خيار لقبول تشغيل فاشل.
4. **ملف جانبي** `evidence/<run>/import.json` يكتبه الاستيراد وحده (ci_run_id, conclusion, head_sha, event, run_attempt, workflow, evidence_branch_commit, imported_at). **لا يُمس `run.json`** بعد إنتاجه (REL-1 C).
5. **قاعدة المدقق**: حكم PASS من `verification-runner` بلا `import.json` خطأ تحت `--strict` وتحذير دونه؛ `import.json` بمعرّف يخالف `run.ci.run_id` خطأ دائمًا؛ أدلة 1.0.0 بلا `import.json` تحذير واحد مجمَّع (حارس للأحكام الـ149 القديمة).
6. **كاتب السجلات واحد** (REL-5 A): العقد `lease` يُجعل null مع السبب في `unknown_fields`، وتنفيذ البند 79 من البرومبت متطلب مؤجل شرطه أن يسبق أي كاتب ثانٍ.

## البدائل المرفوضة

- REL-1 A: العامل من البيئة بنص حر: يُزوَّر. REL-1 B: ادعاء ذاتي داخل `run.json`. كتابة قيم API فوق `run.json`: تكرر عيب تعديل الدليل بعد إنتاجه.
- خيار `--accept-failed` في الاستيراد: يعيد الثغرة من بابها.
- `lease` جديد بلا أداة تكتسبه أو تجدده (REL-5 B): يوهم بحماية.

## الثمن والمخاطر

- يحتاج الاستيراد إلى `gh` مصادق؛ جلسة بلا gh تُحجب ويُرفع الأمر للمالك.
- `headSha` في أحداث pull_request هو رأس الفرع لا التزام الدمج؛ قاعدة السلف تستعمل headSha.
- مطابقة ملف سير العمل بايتيًا وبصمة سجل التشغيل مؤجلتان (secAssurance (ج)).

## الدليل

TST-M0-007 (`tests/test_evidence_provenance.py`)؛ تحديث TST-M0-003 وTST-M0-005؛ أول استيراد بالأداة المفحوصة هو دليل إغلاق WP-65.
