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
import printer as pt
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60


#======================================#
# INDICES DE CABECERA IP               #
#======================================#
#   S = Start
#   E = End
#   I = Index
# Cabecera sin opciones = 20 bytes = 160 bits

VERSION_AND_IHL_I = 0 # 4 bits + 4 bits
TYPE_OF_SERVICE_I = 1 # 1 byte
TOTAL_LENGTH_S = 2 #2 bytes
TOTAL_LENGTH_E = 3+1
IPID_S = 4 #2 bytes
IPID_E = 5+1
FLAGS_I = 6 #3 bits
OFFSET_S = 6 #13 bits
OFFSET_E = 6+2
TIME_TO_LIVE_I = 8 #1 byte
PROTOCOL_I = 9 #1 byte
IP_CHECKSUM_S = 10 #2 bytes
IP_CHECKSUM_E = 11+1
IP_ORIG_S = 12 #4 bytes
IP_ORIG_E = 15+1
IP_DEST_S = 16 #4 bytes
IP_DEST_E = 19+1
OPTIONS_S = 20 #Variable, desde 0 hasta 40 bytes y debe ser multiplo de 4 bytes


LENGTH_IP_HEADER = 20
TTL = 65



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
    logging.debug("[FUNC] process_IP_datagram")
    ip_version = (data[VERSION_AND_IHL_I] & 0b11110000) >> 4
    ihl        = (data[VERSION_AND_IHL_I] & 0b00001111) >> 0
    typeof_service = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    ipid = struct.unpack('!H', data[4:6])[0]
    flag_reserved = (data[FLAGS_I] & 0b10000000) >> 7
    flag_df       = (data[FLAGS_I] & 0b01000000) >> 6
    flag_mf       = (data[FLAGS_I] & 0b00100000) >> 5


    offset = struct.unpack('!H', data[OFFSET_S:OFFSET_E])[0] & 0x1FFF
    time_to_live = data[TIME_TO_LIVE_I]
    protocol = data[PROTOCOL_I]
    checksum = struct.unpack('H', data[IP_CHECKSUM_S:IP_CHECKSUM_E])[0]
    src_ip  = struct.unpack('!I', data[IP_ORIG_S:IP_ORIG_E])[0]
    dest_ip = struct.unpack('!I', data[IP_DEST_S:IP_DEST_E])[0]

    # Calcular datos reales
    ihl *= 4
    offset *= 8

    # NOTE: Maybe we gotta do smth about options, probably not

    # Si el checksum no es correcto se descarta el paquete
    if checksum != chksum(data[0:IP_CHECKSUM_S] + struct.pack('!H', 0) + data[IP_CHECKSUM_E:20]):
        logging.debug("Los checksum no coinciden")
        return

    # Si hay más fragmentos, devolver (no reensamblamos)
    if offset != 0:
        logging.debug(f'Recibido paquete con offset {offset}')
        return


    logging.debug( 'Trama IP recibida:')
    logging.debug(f'   - Header length: {ihl}')
    logging.debug(f'   - IP ID:         {ipid}')
    logging.debug(f'   - Total length:  {total_length}')
    logging.debug(f'   - Flag DF:       {flag_df}')
    logging.debug(f'   - Flag MF:       {flag_mf}')
    logging.debug(f'   - Offset:        {offset}')
    logging.debug(f'   - Source IP:     {pt.IP_to_str(src_ip)}')
    logging.debug(f'   - Dest IP:       {pt.IP_to_str(dest_ip)}')
    logging.debug(f'   - Protocol:      {protocol}')


    callback = protocols.get(protocol, None)
    if callback is not None:
        callback(None, header, data[ihl:], src_ip)




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

    global myIP, myMtu, netmask, defaultGW,ipOpts,IPID
    logging.debug("[FUNC] initIP")
    ret = initARP(interface)
    if ret != 0:
        return False


    # Set IP options
    ipOpts = opts
    if opts is not None:
        len_opts = len(opts)
        if len_opts > 40:
            logging.error('La longitud de las opciones no puede ser superior a 40')
            return False

        # Si la longitud no es multiplo de 4, rellenar con 0
        mod = len_opts % 4
        if mod != 0:
            for _ in range(4 - mod):
                ipOpts += struct.pack('B', 0)


    # TODO: Almacenar en variables globales
    myIP = getIP(interface)
    myMtu = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    ipOpts = opts
    registerEthCallback(process_IP_datagram, 0x0800)
    IPID = 3

    return True


def sendIPDatagram(dstIP,data,protocol):
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
    global IPID, ipOpts, myMtu, netmask, myIP, defaultGW
    logging.debug("[FUNC] sendIPDatagram")
    st = 0  # Controla si se ha enviado bien el datagrama Ethernet

    if dstIP is None:
        logging.error("Dest IP is None")
        return False

    # Obtener la MAC de destino. Si la dirección IP de destino está en la misma subred
    # hacer un ARP Resolution. Si no, mandar al Gateway para que la envie a la Internet
    if (myIP & netmask) == (dstIP & netmask):
        IP_to_resolve = dstIP
    else:
        IP_to_resolve = defaultGW

    dstMAC = ARPResolution(IP_to_resolve)
    if dstMAC is None:
        logging.error("No se pudo resolver la dirección IP")
        return False


    # Determinar si se debe fragmentar
    len_data = len(data)
    len_ipOpts = 0 if ipOpts is None else len(ipOpts)
    len_header = LENGTH_IP_HEADER + len_ipOpts
    max_data_per_fragment = myMtu - len_header

    n_comp_fragments = 0    # Numero de fragmentos con longitud maxima
    n_part_fragments = 0    # Numero de fragmentos sin longitud maxima

    # Determinar si se partir los datos en varios fragmentos
    if len_data > max_data_per_fragment:
        # Si la longitud de los datos utiles no es multiplo de 8 se hace que si lo sea
        if (max_data_per_fragment % 8) != 0:
            max_data_per_fragment -= max_data_per_fragment % 8

        n_comp_fragments = len_data // max_data_per_fragment
        if (len_data % max_data_per_fragment) != 0:
            n_part_fragments = 1

    # Hay que enviar un unico fragmento de longitud maxima
    elif len_data == max_data_per_fragment:
        n_comp_fragments = 1

    # Hay que enviar un unico fragmento sin longitud maxima
    else:
        n_part_fragments = 1


    n_fragments = n_comp_fragments + n_part_fragments

    # Calcular bandera de fragmentacion de datagrama
    flag_reserved = 0
    if n_fragments > 1:
        flag_df = 1
    else:
        flag_df = 0

    # Construir y enviar fragmentos
    len_fragment = max_data_per_fragment + len_header
    ipv_and_ihl = (0x4 << 4) + (len_header) // 4

    for i in range(n_comp_fragments):
        logging.debug(f'Fragment {i+1} / {n_fragments} : size={len_fragment}')
        datagram = bytearray(20)
        datagram[VERSION_AND_IHL_I] = ipv_and_ihl
        datagram[TYPE_OF_SERVICE_I] = 1
        datagram[TOTAL_LENGTH_S:TOTAL_LENGTH_E] = struct.pack('!H', len_fragment)
        datagram[IPID_S:IPID_E] = struct.pack('!H', IPID)

        if i < n_fragments - 1:
            flag_mf = 1
        else:
            flag_mf = 0


        offset = (i * max_data_per_fragment) // 8

        flags_and_offset =  (flag_reserved << 15) + \
                            (flag_mf << 14) + \
                            (flag_df << 13) + \
                            offset

        datagram[OFFSET_S:OFFSET_E] = struct.pack('!H', flags_and_offset)
        datagram[TIME_TO_LIVE_I] = TTL
        datagram[PROTOCOL_I] = protocol
        datagram[IP_CHECKSUM_S:IP_CHECKSUM_E] = struct.pack('!H', 0)
        datagram[IP_ORIG_S:IP_ORIG_E] = struct.pack('!I', myIP)
        datagram[IP_DEST_S:IP_DEST_E] = struct.pack('!I', dstIP)

        # Calculate checksum
        datagram[IP_CHECKSUM_S:IP_CHECKSUM_E] = struct.pack('H', chksum(datagram[0:20])) 

        # Build final datagram
        datagram = bytes(datagram[0:20]) + (b'' if ipOpts is None else ipOpts) + bytes(data)

        # Send datagram
        st += sendEthernetFrame(datagram, len_fragment, ETHERTYPE_IP, dstMAC)



    if n_part_fragments != 0:
        len_fragment = len_data % max_data_per_fragment + len_header
        ipv_and_ihl = (0x4 << 4) + (len_header) // 4

        logging.debug(f'Fragment {n_fragments} / {n_fragments} : size={len_fragment}')
        datagram = bytearray(20)
        datagram[VERSION_AND_IHL_I] = ipv_and_ihl
        datagram[TYPE_OF_SERVICE_I] = 1
        datagram[TOTAL_LENGTH_S:TOTAL_LENGTH_E] = struct.pack('!H', len_fragment)
        datagram[IPID_S:IPID_E] = struct.pack('!H', IPID)

        flag_mf = 0
        offset = (n_comp_fragments * max_data_per_fragment) // 8

        flags_and_offset =  (flag_reserved << 15) + \
                            (flag_mf << 14) + \
                            (flag_df << 13) + \
                            offset

        datagram[OFFSET_S:OFFSET_E] = struct.pack('!H', flags_and_offset)
        datagram[TIME_TO_LIVE_I] = TTL
        datagram[PROTOCOL_I] = protocol
        datagram[IP_CHECKSUM_S:IP_CHECKSUM_E] = struct.pack('!H', 0)
        datagram[IP_ORIG_S:IP_ORIG_E] = struct.pack('!I', myIP)
        datagram[IP_DEST_S:IP_DEST_E] = struct.pack('!I', dstIP)

        # Calculate checksum
        datagram[IP_CHECKSUM_S:IP_CHECKSUM_E] = struct.pack('H', chksum(datagram[0:20])) 

        # Build final datagram
        datagram = bytes(datagram[0:20]) + (b'' if ipOpts is None else ipOpts) + bytes(data)

        # Send datagram
        st += sendEthernetFrame(datagram, len_fragment, ETHERTYPE_IP, dstMAC)


    IPID += 1

    return True if st == 0 else False
