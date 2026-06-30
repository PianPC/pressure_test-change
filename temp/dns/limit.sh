# 1) 启用 ifb，重定向 ingress 到 ifb0
sudo modprobe ifb
sudo ip link set dev ifb0 up

sudo tc qdisc del dev eth0 ingress 2>/dev/null
sudo tc qdisc add dev eth0 handle ffff: ingress
sudo tc filter add dev eth0 parent ffff: protocol ip u32 match u32 0 0 \
  action mirred egress redirect dev ifb0

# 2) 在 ifb0 上建立 HTB class 并把 dport 80 的包放到该 class（rate 可设置为很低 e.g. 50kbit）
sudo tc qdisc del dev ifb0 root 2>/dev/null
sudo tc qdisc add dev ifb0 root handle 1: htb default 10
sudo tc class add dev ifb0 parent 1: classid 1:10 htb rate 50kbit ceil 50kbit burst 1500

# 3) 匹配 UDP/TCP 到 80（如果你的攻击是 UDP 响应，匹配 udp；匹配 tcp 可同时写两条）
sudo tc filter add dev ifb0 protocol ip parent 1: prio 1 u32 \
  match ip dport 80 0xffff match ip protocol 17 0xff \
  flowid 1:10
