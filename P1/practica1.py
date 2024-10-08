# !/usr/bin/python3
# -*- coding: utf-8 -*_

'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autores:
    	- Javier Ramos <javier.ramos@uam.es> 2020 EPS-UAM
     	- Pablo Tejero Lascorz (pablo.tejerol@estudiante.uam.es)
      	- Roberto Martin Alonso (roberto.martinalonso@estudiante.uam.es)
    Grupo 1313
    Pareja 3
'''

import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging
import os
from rc1_pcap import *

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60


class mutable_timeval:
	"""

	"""

	def __init__(self, sec: int, usec: int):
		self.sec = sec
		self.usec = usec

	def set_val(self, sec: int, usec: int)-> None:
		self.sec = sec
		self.usec = usec

	def equals(self, sec: int, usec: int)-> bool:
		return self.sec == sec and self.usec == usec

	@classmethod
	def substract(cls, op1, op2):
		sec = op1.sec - op2.sec
		usec = op1.usec - op2.usec

		if usec < 0:
			sec -= 1
			usec += 1000000

		return cls(sec, usec)

start_time = mutable_timeval(0,0)
end_time = mutable_timeval(0,0)


def pdumper_close(pdumper: pcap_dumper_t, pdumper_desc: pcap_t)-> None:
	if pdumper_desc is None:
		return

	if pdumper is not None:
		pcap_dump_close(pdumper)
	
	pcap_close(pdumper_desc)


def end_program():
	"""
	Libera los recursos necesarios e imprime la información sobre
	la ejecución del programa
	"""

	global handle, pdumper_desc_ip, pdumper_desc_no_ip, pdumper_ip, pdumper_no_ip

	# Si se han creado ficheros para guardar paquetes, cerrarlos y liberar los dumpers
	pdumper_close(pdumper_ip, pdumper_desc_ip)
	pdumper_close(pdumper_no_ip, pdumper_desc_no_ip)

	# Cerrar fichero o interfaz de captura
	if handle:
		pcap_close(handle)

	# Imprimir info de la ejecucion
	time_diff = mutable_timeval.substract(end_time, start_time)

	print(f'Number of packages received: {num_paquete}')
	print('Time diff between first and last package: {}.{:06d}'.format(time_diff.sec, time_diff.usec))


def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
	end_program()
		

def procesa_paquete(us,header,data):
	global num_paquete
	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{:06d}'.format(header.len,header.ts.tv_sec,header.ts.tv_usec))
	num_paquete += 1

	#TODO imprimir los N primeros bytes
	bpl = 16
	column = 0
	for byte in data[0:min(args.nbytes, header.caplen)]:
		if bpl == 16:
			print('\n        0x{:08X}:  '.format(column), end='')
			bpl = 0
			column += 16

		print('{:02X} '.format(byte), end='')
		bpl += 1
			
	print('')

	# Actualizar tiempo del ultimo paquete recibido
	if num_paquete == 1:
		start_time.set_val(header.ts.tv_sec, header.ts.tv_usec)

	end_time.set_val(header.ts.tv_sec, header.ts.tv_usec)


	# Escribir paquete en fichero si se ha capturado de una interfaz en vivo
	if args.interface:
		if data[12] == 0x08 and data[13] == 0x00:
			# Paquete con IP
			pcap_dump(pdumper_ip, header, data)
		else:
			pcap_dump(pdumper_no_ip, header, data)



if __name__ == "__main__":
	global args,handle, dumper_ip, pdumper_no_ip, pdumper_desc_ip, pdumper_desc_no_ip
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--npkt', dest='npkt', type=int, default=50,help='Número de paquetes a capturar')
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


	errbuf = bytearray()		# Byte array for error messages
	handle = None				# Descriptor of any open trace (either file or interface)
	pdumper_desc_ip = None		# File descriptor for file to dump all packages that follow IP protocol
	pdumper_desc_no_ip = None	# File descriptor for file to dump all packages that do not follow IP protocol
	pdumper_ip = None			# Pdumper object for file to dump all packages that follow IP protocol
	pdumper_no_ip = None		# Pdumper object for file to dump all packages that do not follow IP protocol

# <CODIGO_NUESTRO>
	if args.tracefile:
		# Abrir el archivo .pcap con trafico guardado
		handle = pcap_open_offline(args.tracefile, errbuf)
	elif args.interface:
		# Abrir la interfaz para captura en vivo de trafico
		handle = pcap_open_live(args.interface, args.nbytes, PROMISC, TO_MS, errbuf)
		if handle is None:
			logging.error('[ERROR]: Failed to open interface: ' + errbuf.decode())
			end_program()
			sys.exit(-1)

		# Crear ficheros y dumpers para guardar los paquetes capturados
		if not os.path.exists('./capturas'):
			os.mkdir('./capturas')

		current_time_sec = time.time()
		pdumper_desc_ip         = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
		pdumper_desc_no_ip = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
		pdumper_ip         = pcap_dump_open(pdumper_desc_ip,    './capturas/captura.' + args.interface + '.' + f'{current_time_sec}' + '.pcap')
		pdumper_no_ip = pcap_dump_open(pdumper_desc_no_ip, './capturas/capturaNOIP.'     + args.interface + '.' + f'{current_time_sec}' + '.pcap')

		if pdumper_ip is None or pdumper_no_ip is None:
			logging.error("[ERROR]: Failed to create pdumper")
			end_program()
			sys.exit(-1)


	if handle is None:
		logging.error('[ERROR]: Failed to open tracefile: ' + errbuf.decode())
		end_program()
		sys.exit(-1)

# </CODIGO_NUESTRO>

	ret = pcap_loop(handle,args.npkt,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))


	# Liberar recursos y mostrar información de la ejecución
	end_program()
