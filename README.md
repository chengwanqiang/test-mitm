# test-mitm
# # 运行test-mitm项目使用的命令行命令
# # # stack exec test-mitm-exe 3000
# # # iptables -t nat -I PREROUTING -p tcp --dport 7200:7250 -j REDIRECT --to-ports 3000
# # # iptables -t nat -A POSTROUTING -j MASQUERADE
# # 启用代理服务器的转发功能
# # # echo 1 > /proc/sys/net/ipv4/ip_forward
# # # iptables -t nat -S