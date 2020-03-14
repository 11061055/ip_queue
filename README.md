# ip_queue

从内核获取网络数据包,进行 NAT。

背景是 专线容灾  和  网络切换。

基于 IP_QUEUE 的数据包处理程序，可修改IP数据报、TCP数据报不同字段，实现诸如 NAT 负载均衡 入侵检测 等功能。

![curl](https://github.com/11061055/ip_queue/blob/master/images/nat.png)

如上图，向 39.156.69.79 发起请求，数据被发送到 111.202.103.60，应用保持无感知。

Refer to: http://git.netfilter.org/iptables/tree/libipq/libipq.c
Refer to: https://github.com/cernekee/iptables
