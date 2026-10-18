# عقد الشبكة — الإصدار 1 جزء أ: الواجهة (WP-27، ADR-0017)؛ وجزء ب: الخدمة (WP-28؛ TCP مسودة WP-29)

الجزء أ مجمَّد (أُغلق WP-27 بدليل CI run 39134727743)؛ الجزء ب مسودة تخطيط تُجمَّد مع حزمتها. ما لم يُنفَّذ لا يُعدّ مدعومًا. الكود: `kernel/src/drivers/virtio_net.rs` (التعريف)، `kernel/src/net.rs` (الطبقة والاستطلاع)، `kernel/src/object/nic.rs` (الكائن)، `kernel/src/syscall/mod.rs` (النداءات 27–31)، `user/apps/netprobe` (الاختبار من حلقة 3).

## أ. الواجهة (الإصدار 1، syscall.md v1.6)

- **التعريف**: virtio-net بالناقل الحديث نفسه (ADR-0013؛ Virtio 1.3 §5.1، S51): معرّف PCI `0x1041`، السمات المقبولة `VERSION_1 | MAC | STATUS` فقط (لا تفريغ أعباء ولا MRG_RXBUF)، طابوران (استقبال 0، إرسال 1) من 16 واصفًا، رأس `virtio_net_hdr` 12 بايت مصفّر عند الإرسال، إطارات 14..=1514 بايت.
- **نموذج DMA** (threat-model): كل عناوين الواصفات إطارات يملكها التعريف (18 إطارًا ثابتًا: صفحتا الطابورين + 16 خانة بـ 2 KiB لكل اتجاه)، ولا يُعطى الجهاز عنوانًا أو طولًا من مصدر آخر؛ الإطار يُنسخ من/إلى خانة التعريف. ما يتجاوز الحدود يُعدّ (`rx_bad`) ويُسقط.
- **الاستطلاع**: لا مقاطعة للجهاز بعد (I/O APIC مقنَّع، R-23): نبضة المؤقت على المعالج 0 (1 kHz) تفحص حلقة الاستخدام وتوقظ منتظري الكائن؛ أقصى كمون وصول ≈ 1 ms.
- **الكائن** `Object::Nic` (رمز النوع 7): واحد لكل نظام تنشئه النواة وتسلّمه لمدير الخدمات مقبضًا أوليًا، وهو يسلّمه للخدمة المسماة `net` (services.md §4). الحقوق `READ|WRITE|WAIT|DUPLICATE|TRANSFER`: `READ` للاستقبال، `WRITE` للإرسال، `WAIT` للانتظار. إشارة `READABLE` ما دام إطار ينتظر.

| الرقم | الاسم | الوسائط | النتيجة |
|---|---|---|---|
| 28 | `nic_info` | h, out_ptr (16 بايت) | 0؛ `mac[6], link u8 (1 = up), reserved u8, frame_max u16 (1514), queue_size u16, reserved u32` |
| 29 | `nic_send` | h, ptr, len (14..=1514) | 0 عند وضع الإطار في خانة؛ `ERR_SHOULD_WAIT` حين تكون كل الخانات معلّقة (تُحسب `tx_busy`)؛ `ERR_INVALID` للطول؛ `ERR_ACCESS` بلا WRITE؛ `ERR_IO` إن طلب الجهاز إعادة الضبط |
| 30 | `nic_recv` | h, ptr, cap (≥ 1514) | طول الإطار المستلم (بلا رأس virtio)، أو `ERR_SHOULD_WAIT`؛ `ERR_INVALID` إن كانت السعة أصغر؛ `ERR_ACCESS` بلا READ |

- **الحدود تحت الضغط** (TST-M4-NET-LIMITS): 64 إرسالًا متتاليًا = 16 مقبولًا و48 `Busy`، لا أكثر من 16 خانة معلّقة أبدًا، كل الخانات تعود بعد أن يستهلكها الجهاز، وعدد الإطارات 18 لا يتغير.
- **المختبر**: شبكة QEMU user-mode (SLIRP؛ S55): الضيف 10.0.2.15، البوابة 10.0.2.2 (MAC `52:55:0a:00:02:02`)، DNS 10.0.2.3؛ ARP للبوابة يُجاب في الإقلاع (`kernel|net|…|selfcheck=1`) وفي TST-M4-NET-LINK من النواة ومن عملية.

## ب. الخدمة `net` (الإصدار 1، WP-28؛ TCP مسودة WP-29)

مجمَّد (أُغلق WP-28 بدليل CI run 39137446701) ما عدا TCP (WP-29، مسودة): أي تغيير في المكدس أو الطلبات = إصدار جديد مع سجل قرار. الكود: `user/apps/netd` (`/SYSTEM/NETD.ELF`، الاسم `net`، تستلم واجهة الشبكة مقبضًا أوليًا ثانيًا من المدير).

- **المكدس** (خاص بالخدمة، لا شيء في النواة): Ethernet؛ ARP (RFC 826، S53) بجدول 8 مدخلات وحلّ محدود (3 طلبات خلال 300 نبضة ثم `ERR ARP`)؛ IPv4 (RFC 791، S56) بلا تجزئة (الحزم المجزّأة تُسقط وتُعدّ `rx_bad`؛ تجزئة الرأس تُفحص؛ TTL 64؛ DF)؛ ICMP (RFC 792 / IANA، S57) ردّ على طلب الصدى الوارد، وطلب صدى بمعرّف ثابت وتسلسل؛ UDP (RFC 768، S58) بتجزئة الرأس الزائف في الاتجاهين؛ عميل DHCP (RFC 2131/2132، S59/S60): DISCOVER/OFFER/REQUEST/ACK مع الخيارات 1 و3 و6 و51 و53 و54 و55، 3 محاولات بمهلة 1500 نبضة، وسطر تشخيص `net|dhcp|ip=…|mask=…|gw=…|dns=…|lease=…|attempt=…`.
- **الحالات الثلاث** (RSK-003): `link` من واجهة النواة؛ `configured` بعد ACK؛ `internet` ∈ {unknown, none, reachable} لا يتغير إلا بـ `PROBE` صريح (نجاح → reachable، فشل → none)، ولا يُفترض أبدًا.
- **السياسة**: `allow_internet=0` افتراضيًا: وجهة خارج الشبكة الفرعية (ليست البوابة ولا بثًّا) → `ERR POLICY` لـ `PING` و`UDP_SEND`؛ `PROBE` مستثنى (فحص النظام نفسه، حمولة ثابتة). التغيير بـ `POLICY internet=0|1` مع مقبض رمز `ADMIN` صالح (بلا مقبض `ERR BAD_REQUEST`؛ رمز بلا ADMIN أو مُبطَل `ERR ACCESS`).
- **الحدود**: 8 عملاء، 16 مقبس UDP (طابور 4 مخططات لكل مقبس، 1024 بايت لكل مخطط؛ الفائض يُسقط ويُعدّ)، إطار ≤ 1514؛ الحزم المشوهة تُعدّ ولا تُسقط الخدمة.

| الطلب (عبر `CONNECT net`) | الردّ |
|---|---|
| `STATUS` | `OK link=<0/1> configured=<0/1> ip=… mask=… gw=… dns=… internet=<unknown/none/reachable> allow_internet=<0/1> rx=… rx_bad=… tx=…` |
| `DHCP` | `OK ip=… mask=… gw=… dns=…` أو `ERR TIMEOUT` |
| `PING <ip> [timeout_ticks]` | `OK rtt=<ticks>`؛ `ERR TIMEOUT`؛ `ERR ARP`؛ `ERR POLICY`؛ `ERR BAD_REQUEST` |
| `PROBE <ip> [timeout_ticks]` | كـ `PING` بلا سياسة، ويحسم `internet` |
| `POLICY internet=<0/1>` + مقبض رمز ADMIN | `OK`؛ `ERR ACCESS`؛ `ERR BAD_REQUEST` |
| `UDP_OPEN <port>` | `OK <sock>`؛ `ERR EXISTS`؛ `ERR FULL` |
| `UDP_SEND <sock> <ip> <port> <data…>` | `OK <len>`؛ `ERR POLICY`؛ `ERR ARP`؛ `ERR BUSY`؛ `ERR BAD_REQUEST` (مقبس ليس للعميل) |
| `UDP_RECV <sock> <timeout_ticks>` | `OK <ip> <port> <data>`؛ `ERR TIMEOUT` |
| `UDP_CLOSE <sock>` | `OK`؛ المقابس تُغلق أيضًا عند إغلاق قناة العميل |
| `TCP_*` | WP-29 |

- **المختبر**: خادم صدى UDP على المضيف (`tools/project.py`، `host_services`) يُوصَل عبر 10.0.2.2 (SLIRP يوجّهه إلى loopback المضيف)؛ الوجهة خارج الشبكة في الاختبارات 192.0.2.1 (TEST-NET-1، RFC 5737) فلا تُجاب أبدًا.
- **الاختبارات الحاكمة**: TST-M4-DHCP، TST-M4-ICMP-ECHO، TST-M4-UDP-ECHO، TST-M4-NET-NO-INTERNET.
