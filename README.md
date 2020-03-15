# ip_queue


从内核获取网络数据包,进行 NAT。

背景是 专线容灾  和  网络切换。

基于 IP_QUEUE 的数据包处理程序，可修改IP数据报、TCP数据报不同字段，实现诸如 NAT 负载均衡 入侵检测 等功能。


![curl](https://github.com/11061055/ip_queue/blob/master/images/nat.png)


如上图，向 39.156.69.79 发起请求，数据被发送到 111.202.103.60，应用保持无感知。


Refer to: https://github.com/cernekee/iptables

Refer to: http://git.netfilter.org/iptables/tree/libipq/libipq.c

Cited by: [网络安全基础](https://github.com/11061055/php-7.3.0-ext-curl/wiki/0.-%E7%BD%91%E7%BB%9C_____%E5%AF%86%E7%A0%81%E5%AD%A6%E4%B8%8E%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8)

Cited by: [内核参数优化](https://github.com/11061055/php-7.3.0-ext-curl/wiki/0.-%E7%BD%91%E7%BB%9C_____linux-%E5%86%85%E6%A0%B8%E5%8F%82%E6%95%B0%E4%BC%98%E5%8C%96)
