'''
    ethmsg.py
    Implementación del protocolo de mensajeria basica para emision de mensajes en tiempo real sobre ethernet.
    Autor: Manuel Ruiz <manuel.ruiz.fernandez@uam.es>
    2024 EPS-UAM
'''

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

ETHTYPE = 0x3003
#Dirección de difusión (Broadcast)
broadcast = bytes([0xFF]*6)




def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_EthMsg_frame
        Descripción: Esta función procesa las tramas mensajes sobre ethernet. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype ETHTYPE (si ha sido registrada en initEth). 
                - Imprimir el contenido de los datos indicando la direccion MAC del remitente, la dirección IP de destino (en notación decimal a.b.c.d), asi como el tiempo de recepcion del mensaje, según el siguiente formato:
					[<segundos.microsegundos>] <MAC> -> <IP>: <mensaje> 
                - En caso de que no exista retornar

        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ethMsg
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    # NOTE: STATUS = Implemented
    # NOTE: TESTED = False
    ip = struct.unpack('!I', data[0:4])[0]
    time_sec = header.ts.tv_sec
    time_usec = header.ts.tv_usec

    mac6 = struct.unpack('!H', srcMac[0:2])[0]
    mac5 = struct.unpack('!H', srcMac[2:4])[0]
    mac4 = struct.unpack('!H', srcMac[4:6])[0]
    mac3 = struct.unpack('!H', srcMac[6:8])[0]
    mac2 = struct.unpack('!H', srcMac[8:10])[0]
    mac1 = struct.unpack('!H', srcMac[10:12])[0]

    ip4 = (ip & 0x000000FF) >> 0x00
    ip3 = (ip & 0x0000FF00) >> 0x08
    ip2 = (ip & 0x00FF0000) >> 0x10
    ip1 = (ip & 0xFF000000) >> 0x18

    str_mac = f'{hex(mac1)}.{hex(mac2)}.{hex(mac3)}.{hex(mac4)}.{hex(mac5)}.{hex(mac6)}'
    str_ip  = f'{ip1}.{ip2}.{ip3}.{ip4}'

    print(f'[{time_sec}.{time_usec}] {str_mac} -> {str_ip}')


def initEthMsg(interface:str) -> int:
    '''
        Nombre: initEthMsg
        Descripción: Esta función construirá inicializará el nivel ethMsg. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_ethMsg_frame con el Ethertype ETHTYPE
        Argumentos:   
			interfaz
    '''
    # TODO : Check if it is needed to add more stuff
    # NOTE : Not tested
    registerEthCallback(process_ethMsg_frame, ETHTYPE)


def sendEthMsg(ip:int, message:bytes) -> bytes:
    '''
        Nombre: sendEthMsg
        Descripción: Esta función mandara un mensaje en broacast 
            
            Esta función debe realizar, al menos, las siguientes tareas:
                - Crear una trama Ehernet con el mensaje remitido
                - Enviar un mensaje en broadcast
		Argumentos:
			ip: Direccion IP a la que remitir el mensaje. Enviar como una palabra de 32 bits en orden de red.
			message: datos con el mensaje a remitir.

        Retorno: 
			Numero de Bytes transmitidos en el mensaje.
			None en caso de que no haya podido emitir el mensaje 
    '''
    # TODO: Control de errores
    # TODO: check if ip es data[0:3] o data[0:4]
    # NOTE: TESTED = False
    data = bytes()
    data += struct.pack('!!I', ip)
    data += message

    return sendEthernetFrame(data, len(data), ETHTYPE, broadcast)
