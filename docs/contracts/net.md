# عقد الشبكة — الإصدار 0 (مسودة M4، ADR-0016)

مسودة تخطيط: تُجمَّد كإصدار 1 عند إغلاق حزمتها بدليل CI؛ ما لم يُنفَّذ منها لا يُعدّ مدعومًا.

- **الخدمة** `netd` فوق تعريف virtio-net (قناة إطارات: `TX frame`, `RX frame`).
- **الحالة**: `link` (الرابط موجود)، `configured` (عنوان IPv4 من DHCP أو ثابت)، `internet` ∈ {unknown, none, reachable} ولا تصبح `reachable` إلا بفحص صريح (`PROBE`) ينجح؛ السياسة `no_internet=1` افتراضيًا ترفض الاتصال خارج الشبكة المحلية بـ`ERR_POLICY`.
- **الطلبات**: `STATUS`، `DHCP`، `PING addr` → rtt_ticks، `UDP_OPEN port`، `UDP_SEND sock addr port data`، `UDP_RECV sock timeout`، `TCP_CONNECT addr port`، `TCP_SEND`, `TCP_RECV`, `TCP_CLOSE`.
- **الحدود**: حزم ≤ 1514 بايت، طابور استقبال 32 إطارًا، 16 مقبسًا لكل عميل؛ الحزم المشوهة تُعدّ وتُسقط ولا تُسقط الخدمة.
