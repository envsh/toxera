relays:

34.59.243.77:4001 — Circuit v2 hop OK

141.95.145.190:4001

45.63.61.139:4001


139.59.119.94:4001

104.131.131.82:4001 96s disconnect

relay的limit.data值一般128K，总流量太少了。

relay的限制太多，总预约数，每ip预约数等，限制都不太够用，很难用！

2026/05/21 12:57:53 [ERR] yamux: keepalive failed: i/o deadline reached

### cmds:

* cmd/detect relay信息检测
* cmd/peer 基础服务端
* cmd/source 基础客户端
* cmd/budgeted-peer 解决relay只转发128k限制的服务端
* cmd/budgeted-connect 解决relay只转发128k限制的客户端
