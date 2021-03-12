# iptv_channel_scanner_linux
原理：  
构造igmp包，然后使用libpcap抓包，获取组播地址和端口。  
need install g++ libpcap
to compile it:  
		g++ -g -o iptvscanner iptvscanner.cpp -lpcap  
usage: 
	./iptvscanner "interfacename" 225.1.1.1 239.3.1.254 > list.txt

e.g $ sudo ./iptvscanner eth0 225.1.1.1 225.2.1.1 > iptv.txt  
