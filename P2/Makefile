.PHONY: deploymn t11 t12

# Starts mininet
deploymn:
	sudo systemctl stop network-manager
	sudo mn --nat
	gterm h1
	gterm h2

t11:
	rm -rf __pycache__
	python3 practica2.py --itf h1-eth0 --debug

t12:
	rm -rf __pycache__
	python3 practica2.py --itf h2-eth0 --debug
