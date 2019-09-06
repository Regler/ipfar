# ipfar
默认是IP分片
-c是重组
-s 后面带参数表示自动抓包条数大小 默认500
-a 后面带参数表示从哪个网口抓包 
-m 表示设置mtu的大小   默认1500
-w 表示最终结果写到哪个文件 默认final.pcap

如本地pcap进行分片
./pcaptest -m 1000 -w output.pacp  input.pcap

自动捕获进行分片
./pcaptest -a ens33 -s 10000 -m 1000 -w output.pcap

重组
./pcaptest -c input.pcap -w output.pcap
