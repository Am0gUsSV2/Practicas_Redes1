IP_1=10.0.0.1
IP_2=10.0.0.2
ICMP_SIZE=33


.PHONY: all host1 host2 launch-mn

all: launch-mn

host1:
	python3 practica3.py --itf h1-eth0 --dstIP $(IP_2) --icmpSize $(ICMP_SIZE) --debug

host2:
	python3 practica3.py --itf h2-eth0 --dstIP $(IP_1) --icmpSize $(ICMP_SIZE) --debug


launch-mn:
	sudo systemctl stop network-manager
	sudo mn --nat
	# gterm h1
	# gterm h2

wireshark:
	sudo wireshark-gtk
