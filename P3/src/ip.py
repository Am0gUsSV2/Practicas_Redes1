'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60


# ====================================#
# INDICES DE CABECERA IP              #
# ====================================#
#   S = Start
#   E = End 
#Cabecera sin opciones = 20 bytes = 160 bits

VERSION_S = 0 #4 bits
VERSION_E = 3+1
IHL_S = 4 #4 bits
IHL_E = 7+1
TYPE_OF_SERVICE_S = 8 #1 byte
TYPE_OF_SERVICE_E = 15+1 
TOTAL_LENGTH_S = 16 #2 bytes
TOTAL_LENGTH_E = 31 + 1
IDENTIFICATION_S = 32 #2 bytes
IDENTIFICATION_E = 47 + 1
FLAGS_S = 48 #3 bits
FLAGS_E = 50 + 1
OFFSET_S = 51 #13 bits
OFFSET_E = 63 + 1
TIME_TO_LIVE_S = 64 #1 byte
TIME_TO_LIVE_E = 71 + 1
PROTOCOL_S = 72 #1 byte
PROTOCOL_E = 79 + 1
HEADER_CHKSUM_S = 80 #2 bytes
HEADER_CHKSUM_E = 95 + 1
IP_ORIG_S = 96 #4 bytes
IP_ORIG_E = 127 + 1
IP_DEST_S = 128 #4 bytes
IP_DEST_E = 159 + 1
OPTIONS_S = 160 #Variable, desde 0 hasta 40 bytes y debe ser multiplo de 4 bytes
OPTIONS_E = 164 + 1

DEF_MTU = 1500 #En bytes
LONG_HEADER_IP = 20



def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0xa29f    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha función 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    # NOTE: STATUS = Implemented
    ip_version = (data[0] & 0b11110000) >> 4
    ihl        = (data[0] & 0b00001111) >> 0
    typeof_service = data[1]
    total_length = struct.unpack('!H', data[2:4])
    ipid = struct.unpack('!H', data[4:6])
    flag_reserved = (data[6] & 0b10000000) >> 7
    flag_df       = (data[6] & 0b01000000) >> 6
    flag_mf       = (data[6] & 0b00100000) >> 5


    offset = struct.unpack('!H', data[6:8])[0] & 0x1FFF
    time_to_live = data[8]
    protocol = data[9]
    checksum = struct.unpack('!H', data[10:12])[0]
    src_ip  = struct.unpack('!I', data[12:16])[0]
    dest_ip = struct.unpack('!I', data[16:20])[0]

    # Calcular datos reales
    ihl *= 4
    offset *= 8

    # NOTE: Maybe we gotta do smth about options, probably not

    # Si el checksum no es correcto se descarta el paquete
    if checksum != chksum(data[0:ihl]):
        return

    # Si hay más fragmentos, devolver (no reensamblamos)
    if offset != 0:
        return

    logging.debug(f'Trama IP recibida:')
    logging.debug(f'   - Header length: {ihl}')
    logging.debug(f'   - IP ID:         {ipid}')
    logging.debug(f'   - Total length:  {total_length}')
    logging.debug(f'   - Flag DF:       {flag_df}')
    logging.debug(f'   - Flag MF:       {flag_mf}')
    logging.debug(f'   - Offset:        {offset}')
    logging.debug(f'   - Source IP:     {src_ip}')
    logging.debug(f'   - Dest IP:       {dest_ip}')
    logging.debug(f'   - Protocol:      {protocol}')


    callback = protocols.get(protocol, None)
    if callback is not None:
        callback(data[60:])




def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    # NOTE: STATUS = Implemented
    protocols[protocol] = callback


def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts,IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    #NOTE: STATUS = Implemented, TEST = Not tested
    ret = initARP(interface)
    if ret != 0:
        return ret
    # TODO: Almacenar en variables globales
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    ipOpts = opts
    registerEthCallback(process_IP_datagram, 0x0800)
    IPID = 3 #NOTE: no se si el numero de pareja se pone asi


def sendIPDatagram(dstIP,data,protocol):
    global IPID
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer uso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    #NOTE: STATUS : Implementing...
    ip_header = bytes()
    if dstIP is None:
        logging.error("Dest IP is None")
        return False
    data_len = len(data)
    long_util_data = MTU - LONG_HEADER_IP
    if data_len > long_util_data:
        if (long_util_data % 8): #Se comprueba si los datos utiles son multiplos de 8
            long_util_data = long_util_data - long_util_data % 8 #Si no son multiplos se hace que el valor maximo de datos utiles si lo sea
        n_fragments = data_len / long_util_data