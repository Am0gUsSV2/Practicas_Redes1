.PHONY: deploymn t11 t12

# Starts mininet
deploymn:
	sudo systemctl stop network-manager
	sudo mn --nat

t11:
	rm -rf __pycache__
	python3 practica2.py --itf h1-eth0 --debug

t12:
	rm -rf __pycache__
	python3 practica2.py --itf h2-eth0 --debug

#Poner maquina con ip determinada
#h1 ifconfig h1-eth0 10.0.0.1 netmask 255.255.255.0	

#Lanzar maquina
#gterm h1

