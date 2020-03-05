# ip_queue

项目背景是专线容灾与网络切换。

基于 IP_QUEUE 的数据包处理程序，可修改IP数据报、TCP数据报不同字段，实现诸如 NAT 负载均衡 入侵检测 等功能。

![curl](https://github.com/11061055/ip_queue/blob/master/images/nat.png)

如上图，向 39.156.69.79 发起请求，数据被发送到 111.202.103.60，应用保持无感知。

Refet to: https://github.com/qris/iptables/blob/master/libipq/libipq.c
