# عقد الشبكة — الإصدار 1: جزء أ الواجهة (WP-27، ADR-0017)؛ جزء ب الخدمة (WP-28)؛ جزء ج TCP (WP-29)

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

## ب. الخدمة `net` (الإصدار 1، WP-28؛ TCP في الجزء ج)

مجمَّد (أُغلق WP-28 بدليل CI run 39137446701؛ TCP في الجزء ج مع WP-29): أي تغيير في المكدس أو الطلبات = إصدار جديد مع سجل قرار. الكود: `user/apps/netd` (`/SYSTEM/NETD.ELF`، الاسم `net`، تستلم واجهة الشبكة مقبضًا أوليًا ثانيًا من المدير).

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
| `TCP_*` | الجزء ج |

- **المختبر**: خادم صدى UDP على المضيف (`tools/project.py`، `host_services`) يُوصَل عبر 10.0.2.2 (SLIRP يوجّهه إلى loopback المضيف)؛ الوجهة خارج الشبكة في الاختبارات 192.0.2.1 (TEST-NET-1، RFC 5737) فلا تُجاب أبدًا.
- **الاختبارات الحاكمة**: TST-M4-DHCP، TST-M4-ICMP-ECHO، TST-M4-UDP-ECHO، TST-M4-NET-NO-INTERNET.

## ج. TCP في الخدمة `net` (الإصدار 1، WP-29؛ RFC 9293 S61، RFC 6298 S62)

مجمَّد (أُغلق WP-29 بدليل CI run 39139475715): أي تغيير في آلة الحالات أو المؤقت أو الطلبات = إصدار جديد مع سجل قرار. عميل TCP (فتح نشط فقط؛ لا إصغاء في هذا الإصدار) بمقطع واحد قيد الإرسال (stop-and-wait). الكود: `user/apps/netd` (الطلبات `TCP_*`)، `kernel/src/ktest.rs` (`net_tcp_echo`، `net_tcp_retransmit`)، `tools/project.py` (`host_services` نوع `tcp_echo`).

- **الاتصال**: مصافحة ثلاثية SYN / SYN+ACK / ACK (RFC 9293 §3.5)؛ ISN من مولّد خطي مخلوط بالنبضة؛ منفذ محلي دوّار 49152..65535؛ خيار MSS (النوع 2، الطول 4) يُرسَل بقيمة 1024 ويُقرأ من SYN+ACK (الافتراضي 536 عند غيابه، §3.7.1؛ يُحصر في 64..1024)؛ 8 اتصالات في آن؛ معرّف الاتصال `<conn>` (u32 يبدأ من 1) لا يُعاد استخدامه أبدًا.
- **النقل**: مقطع واحد ≤ MSS قيد الإرسال (PSH على البيانات)؛ `TCP_SEND` يقسّم البيانات ويحجز حتى يصل إقرار كل مقطع؛ الاستقبال بالترتيب فقط (مخزن 2048 بايت لكل اتصال، النافذة المعلنة = المتبقي؛ مقطع خارج الترتيب يُسقط ويُعاد الإقرار الحالي)؛ FIN من النظير يُقَرّ ويُسجَّل (EOF).
- **المؤقت (RFC 6298)**: RTO ابتدائي 1000 نبضة (1 ث)؛ أول عينة SRTT=R وRTTVAR=R/2، ثم RTTVAR=(3·RTTVAR+|SRTT−R|)/4 وSRTT=(7·SRTT+R)/8 وRTO=SRTT+max(1,4·RTTVAR) بحد أدنى 1000 وأقصى 60000؛ عند انقضاء المؤقت يُعاد إرسال المقطع غير المُقَرّ وRTO يتضاعف (حتى 60000) ويبقى حتى عينة جديدة؛ لا عينة من مقطع أُعيد إرساله (Karn، §3)؛ بعد SYN أُعيد إرساله يبدأ RTO البيانات من 3000 على الأقل (5.7)؛ بعد 6 إعادات (≈123 ث، RFC 9293 §3.8.3: R2 ≥ 100 ث) تُنهى الوصلة بـ RST للنظير وتصير `CLOSED` بعطل timeout.
- **الإغلاق**: FIN نشط → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT (2000 نبضة ثم تُحرَّر الخانة)؛ بعد FIN النظير → CLOSE-WAIT ثم LAST-ACK → CLOSED؛ CLOSING عند التزامن؛ مهلة 5000 نبضة لمصافحة الإغلاق ثم إنهاء بـ RST. RST من النظير: قبل الاكتمال `ERR REFUSED`، بعده `ERR RESET`. مقطع لا يخص اتصالًا (ولا يحمل RST) يُجاب بـ RST (§3.5.2)؛ FIN مكرر في TIME-WAIT يُقَرّ ثانية.
- **السياسة**: `TCP_CONNECT` إلى وجهة خارج الشبكة الفرعية بلا `allow_internet` → `ERR POLICY`.
- **حقن تشخيصي**: `TCP_INJECT <conn> drop_next=1` يُسقط إرسال الاتصال التالي مرة واحدة (لا يُوضع على السلك والمؤقت يعمل) لاختبار إعادة الإرسال في المختبر.

| الطلب | الردّ |
|---|---|
| `TCP_CONNECT <ip> <port> [timeout_ticks=5000]` | `OK <conn>`؛ `ERR REFUSED` (RST)؛ `ERR TIMEOUT`؛ `ERR POLICY`؛ `ERR ARP`؛ `ERR FULL`؛ `ERR BAD_REQUEST` |
| `TCP_SEND <conn> <data…>` (1..1500 بايت) | `OK <len>` بعد إقرار كل المقاطع؛ `ERR RESET`؛ `ERR TIMEOUT` (حد إعادة الإرسال)؛ `ERR CLOSED` |
| `TCP_RECV <conn> <timeout_ticks>` | `OK <data>` (≤ 1500 بايت مما وصل بالترتيب)؛ `ERR TIMEOUT`؛ `ERR CLOSED` (EOF أو منتهٍ)؛ `ERR RESET` |
| `TCP_CLOSE <conn>` | `OK` ويُحرَّر المعرّف |
| `TCP_STATUS <conn>` | `OK state=<CLOSED/SYN-SENT/ESTABLISHED/FIN-WAIT-1/FIN-WAIT-2/CLOSE-WAIT/LAST-ACK/CLOSING/TIME-WAIT> retransmits=<n> rto=<ticks> srtt=<ticks> mss=<n> unacked=<bytes> rx_pending=<bytes>` |
| `TCP_INJECT <conn> drop_next=1` | `OK`؛ `ERR BAD_REQUEST` |
| أيٌّ منها بمعرّف محرَّر أو ليس للعميل | `ERR CLOSED`؛ معرّف غير رقمي `ERR BAD_REQUEST` |

- عند إغلاق قناة العميل تُنهى اتصالاته بـ RST وتُحرَّر خاناتها.
- **المختبر**: خادم صدى TCP على المضيف (`host_services` نوع `tcp_echo`، 127.0.0.1:17008) عبر 10.0.2.2؛ المنفذ 17009 بلا مُصغٍ فيرفضه المضيف وSLIRP يحوّل الرفض إلى RST للضيف.
- **الاختبارات الحاكمة**: TST-M4-TCP-ECHO، TST-M4-TCP-RETRANSMIT.
