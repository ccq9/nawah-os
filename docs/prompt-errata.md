# prompt-errata — تفسيرات معتمدة لنص OS-EXEC-AR 3.2 (دون تعديل النص أو بصمته)

errata_version: 1

| # | الموضع | الملاحظة | التفسير المعتمد | التاريخ |
|---|---|---|---|---|
| E-01 | البند 20، أوامر tools/project.py | الأمر `test --suite M1` يفترض هدفًا ضيفًا فقط؛ اختبارات المضيف (وحدات المدقق) تحتاج هدفًا أيضًا | أُضيف الهدف `host` لأجنحة المضيف: `test --target host --suite M0` | 2026-10-17 |
| E-02 | البند 7 جدول المخرجات | `docs/tests.json` غير مذكور رغم أن requirements/work-items تشير إلى test_ids | سجل الاختبارات ملف مستقل docs/tests.json بمخطط tests.schema.json | 2026-10-17 |
