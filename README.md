# iptv_channel_scanner_linux
原理：

构造igmp包，然后使用libpcap抓包，获取组播地址和端口。  

it could run any linux devices ,e.g.x86&arm system but need install g++ libpcap

to compile it:  

	$ g++ -g -o iptvscanner iptvscanner.cpp -lpcap

usage: 

	$sudo ./iptvscanner "interfacename" 225.1.1.1 239.3.1.254 > list.txt

e.g

	$sudo ./iptvscanner eth0 225.1.1.1 225.2.1.1 > iptv.txt 
Please note that the three major operators of China Telecom, China Unicom and China Mobile may operate in different regions with different IPTV certification methods. This procedure is only applicable to operators that have opened IPTV VLANs and IPTV uses multicast certification. Also note that you need to understand the local multicast address range. 
