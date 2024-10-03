'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60

start_time = None
end_time = None


def end_program():
	"""
	Libera los recursos necesarios e imprime la información sobre
	la ejecución del programa
	"""

	global handle

	# Si se ha creado un dumper cerrarlo
	if  pdumper_desc is not None:
		pcap_dump_close(pdumper_desc)
	if handle is not None:
		pcap_close(handle)

	# Imprimir info de la ejecucion
	time_diff = 0
	if start_time is not None:
		time_diff = start_time - end_time

	print(f'Number of packages received: {num_paquete}')
	print(f'Time diff between first and last package: {time_diff}')


def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
		end_program()
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper
	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_sec))
	num_paquete += 1

	#TODO imprimir los N primeros bytes
	#Escribir el tráfico al fichero de captura con el offset temporal
	if start_time is None:
		start_time = time
		end_time = time
	else:
		end_time = time

	offset_temporal = end_time - start_time

	
if __name__ == "__main__":
	global pdumper,args,handle, pdumper_desc
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

# <CODIGO_NUESTRO>
	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	if args.tracefile is not False and args.interface is not False:
		logging.error('Debes elegir una traza o una interfaz, no los dos a la vez')
		parser.print_help()
		sys.exit(-1)
# </CODIGO_NUESTRO>

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper = None
	pdumper_desc = None

# <CODIGO_NUESTRO>
	if args.tracefile is not False:
		# Abrir el archivo .pcap con trafico guardado
		handle = pcap_open_offline(args.tracefile, errbuf)
	else:
		# Abrir la interfaz para captura en vivo de trafico
		handle = pcap_open_live(args.interface, args.nbytes, PROMISC, TO_MS, errbuf)

	if handle is None:
		print(errbuf.decode())
		sys.exit(-1)

	if args.interface is not None:
		# Abrir un dumper para volcar el tráfico capturado
		pdumper_desc = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
		pdumper = pcap_dump_open(pdumper_desc, "salida.pcap")
		if pdumper is None:
			print("[ERROR]: Failed to create pdumper")
			end_program()
			sys.exit(-1)
# </CODIGO_NUESTRO>

	ret = pcap_loop(handle,50,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))

	# TODO: Printear info de ejecucion


	# Si se ha creado un dumper cerrarlo
	pcap_dump_close(pdumper_desc)
