'''
    icmp.py
    
    Funciones necesarias para implementar el nivel UDP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
import struct

UDP_HLEN = 8
UDP_PROTO = 17

###########################
# INDICES DE CABECERA UDP #
###########################
#S = Start
#E = End 
SRC_PORT_S = 0 #2 bytes
SRC_PORT_E = 15 + 1
DST_PORT_S = 16 #2 bytes
DST_PORT_E = 31 + 1
UDP_LENGTH_S = 32 #2 bytes
UDP_LENGTH_E = 47 + 1
UDP_CHKSUM_S = 48 #2 bytes
UDP_CHKSUM_E = 63 + 1
#DATA_OCTETS...

def getUDPSourcePort():
    '''
        Nombre: getUDPSourcePort
        Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
        Argumentos:
            -Ninguno
        Retorno: Entero de 16 bits con el número de puerto origen disponible
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum =  s.getsockname()[1]
    s.close()
    return portNum

def process_UDP_datagram(us,header,data,srcIP):
    '''
        Nombre: process_UDP_datagram
        Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
        un 17 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera UDP
            -Loggear (usando logging.debug) los siguientes campos:
                -Puerto origen
                -Puerto destino
                -Datos contenidos en el datagrama UDP

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del datagrama UDP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
    '''
    # NOTE: STATUS = Implemented
    src_port = struct.unpack('!H', data[SRC_PORT_S:SRC_PORT_E]) 
    dst_port = struct.unpack('!H', data[DST_PORT_S:DST_PORT_E]) 
    length = struct.unpack('!H', data[UDP_LENGTH_S:UDP_LENGTH_E]) 

    logging.debug( 'Datagrama UDP recibido:')
    logging.debug(f'   - Src Port: {src_port}')
    logging.debug(f'   - Dst Port: {dst_port}')
    logging.debug(f'   - Data:     {data[CHECKSUM_E:]}')



def sendUDPDatagram(data,dstPort,dstIP):
    '''
        Nombre: sendUDPDatagram
        Descripción: Esta función construye un datagrama UDP y lo envía
        Esta función debe realizar, al menos, las siguientes tareas:
            -Construir la cabecera UDP:
                -El puerto origen lo obtendremos llamando a getUDPSourcePort
                -El valor de checksum lo pondremos siempre a 0
            -Añadir los datos
            -Enviar el datagrama resultante llamando a sendIPDatagram

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el datagrama UDP
            -dstPort: entero de 16 bits que indica el número de puerto destino a usar
            -dstIP: entero de 32 bits con la IP destino del datagrama UDP
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
    '''
    udp_datagram = bytes()
    udp_datagram += struct.pack('!H', getUDPSourcePort())
    udp_datagram += struct.pack('!H', dstPort)
    udp_datagram += struct.pack('!H', 64 + len(data))
    udp_datagram += struct.pack('!H', 0)
    udp_datagram += data

    return sendIPDatagram(dstIP, udp_datagram, UDP_PROTO)


def initUDP():
    '''
        Nombre: initUDP
        Descripción: Esta función inicializa el nivel UDP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17

        Argumentos:
            -Ninguno
        Retorno: Ninguno
    '''
    registerIPProtocol(process_UDP_datagram, UDP_PROTO)
