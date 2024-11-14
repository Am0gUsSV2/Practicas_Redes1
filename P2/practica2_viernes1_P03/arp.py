'''
    arp.py
    Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autores: Pablo Tejero Lascorz, pablo.tejerol@estudiante.uam.es
             Roberto Martin Alonso, roberto.martinalonso@estudiante.uam.es
    2019 EPS-UAM
'''
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from ethernet import *
from expiringdict import ExpiringDict
import printer as pt

#Semáforo global
globalLock =Lock()
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6

#Variable que alamacenará que dirección IP se está intentando resolver
requestedIP = None
#Variable que alamacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False

#Variable para proteger la caché
cacheLock = Lock()
#Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)

# Indices para cabeceras de tramas ARP
#   S : Start index
#   E : End index
#   I : Index
HW_T_S   = 0    # Hardware type
HW_T_E   = 1+1
PR_T_S   = 2    # Protocol type
PR_T_E   = 3+1
HW_S_I   = 4    # Hardware size
PR_S_I   = 5    # Protocol size
OPCODE_S = 6    # Opcode
OPCODE_E = 7+1
SMAC_S   = 8    # Sender (orig) MAC
SMAC_E   = 13+1
SIP_S    = 14   # Target (dest) MAC
SIP_E    = 17+1
TMAC_S   = 18   # Sender (orig) IP
TMAC_E   = 23+1
TIP_S    = 24   # Target (dest) IP
TIP_E    = 27+1


# Otras macros
HW_TYPE_ETHERNET   = 0x0001   # Indica que las direcciones de nivel de enlace son de tipo Ethernet
PR_TYPE_IPV4       = 0x0800   # Indica que el protocolo de nivel de red es IPv4
ETHERNET_SIZE      = 0x06        # Tamano de direcciones Ethernet
IPV4_SIZE          = 0x04        # Tamano de direcciones IPv4
OPCODE_ARP_REQUEST = 0x0001 # El tipo de mensaje ARP es Request
OPCODE_ARP_REPLY   = 0x0002 # El tipo de mensaje ARP es Reply

ETHERTYPE_IP       =  0x0800      # Protocolo de nivel superior: IP
ETHERTYPE_ARP      = 0x0806      # Protocolo de nivel superior: ARP


def getIP(interface:str) -> int:
    '''
        Nombre: getIP
        Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
        Argumentos:
            -interface: nombre de la interfaz
        Retorno: Entero de 32 bits con la dirección IP de la interfaz
    '''
    logging.debug("[FUCN] getIP")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def printCache()->None:
    '''
        Nombre: printCache
        Descripción: Esta función imprime la caché ARP
        Argumentos: Ninguno
        Retorno: Ninguno
    '''
    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))


def processARPRequest(data:bytes,MAC:bytes)->None:
    '''
        Nombre: processARPRequest
        Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
                    -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    logging.debug("[FUNC] processARPRequest")
    mac_orig: bytes = data[SMAC_S:SMAC_E]
    ip_orig: bytes  = struct.unpack('!I', data[SIP_S:SIP_E])[0]
    ip_dest: bytes  = struct.unpack('!I', data[TIP_S:TIP_E])[0]

    if mac_orig != MAC:
        return

    if ip_dest != myIP:
        return

    response = createARPReply(ip_orig, mac_orig)

    sendEthernetFrame(response, len(response), ETHERTYPE_ARP, mac_orig)


def processARPReply(data:bytes,MAC:bytes)->None:
    '''
        Nombre: processARPReply
        Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la MAC destino contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                    -Copiar la MAC origen a la variable global resolvedMAC
                    -Añadir a la caché ARP la asociación MAC/IP.
                    -Cambiar el valor de la variable awaitingResponse a False
                    -Cambiar el valor de la variable requestedIP a None
        Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    global requestedIP,resolvedMAC,awaitingResponse,cache
    global myIP, globalLock

    logging.debug('[FUNC] processARPReply')

    mac_orig: bytes = data[SMAC_S:SMAC_E]
    mac_dest: bytes = data[TMAC_S:TMAC_E] #NOTE Not used
    ip_orig: bytes  = struct.unpack('!I', data[SIP_S:SIP_E])[0]
    ip_dest: bytes  = struct.unpack('!I', data[TIP_S:TIP_E])[0]

    if mac_orig != MAC:
        return
    
    # Retornamos si el paquete no es para nosotros
    if ip_dest != myIP:
        return

    with globalLock:
        # Retornar si el emisor de la respuesta ARP no coincide con el esperado
        if ip_orig != requestedIP:
            return

        resolvedMAC = mac_orig
        awaitingResponse = False
        requestedIP = None

    # Almacenar en la cache el par IP/MAC
    with cacheLock:
        cache[ip_orig] = mac_orig      


def createARPRequest(ip:int) -> bytes:
    '''
        Nombre: createARPRequest
        Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
        Argumentos:
            -ip: dirección a resolver 
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP

    logging.debug("[FUNC] createARPRequest")

    request = bytes()
    request += struct.pack('!H', HW_TYPE_ETHERNET)
    request += struct.pack('!H', PR_TYPE_IPV4)
    request += struct.pack('!B', ETHERNET_SIZE)
    request += struct.pack('!B', IPV4_SIZE)
    request += struct.pack('!H', OPCODE_ARP_REQUEST)
    request += myMAC
    request += struct.pack('!I', myIP)
    request += broadcastAddr
    request += struct.pack('!I', ip)

    pt.print_ARP_header(request, 0)

    return request


def createARPReply(IP:int ,MAC:bytes) -> bytes:
    '''
        Nombre: createARPReply
        Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
        Argumentos: 
            -IP: dirección IP a la que contestar
            -MAC: dirección MAC a la que contestar
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP

    logging.debug("[FUCN] createARPReply")

    request = bytes()
    request += struct.pack('!H', HW_TYPE_ETHERNET)
    request += struct.pack('!H', PR_TYPE_IPV4)
    request += struct.pack('!B', ETHERNET_SIZE)
    request += struct.pack('!B', IPV4_SIZE)
    request += struct.pack('!H', OPCODE_ARP_REPLY)
    request += myMAC
    request += struct.pack('!I', myIP)
    request += MAC
    request += struct.pack('!I', IP)

    pt.print_ARP_header(request, 0)

    return request


def process_arp_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_arp_frame
        Descripción: Esta función procesa las tramas ARP. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP). 
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
                -Extraer el campo opcode
                -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
                -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
                -Si es otro opcode retornar de la función
                -En caso de que no exista retornar
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ARP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    # Extraer la cabecera comun de ARP
    logging.debug("[FUNC] process_arp_frame")
    hw_type = struct.unpack('!H', data[HW_T_S:HW_T_E])[0]
    hw_size = struct.unpack('B', data[HW_S_I:HW_S_I + 1])[0]
    protocol_type = struct.unpack('!H', data[PR_T_S:PR_T_E])[0]
    protocol_size = struct.unpack('B', data[PR_S_I:PR_S_I + 1])[0]

    if  hw_type != HW_TYPE_ETHERNET or \
        protocol_type != PR_TYPE_IPV4 or \
        hw_size != ETHERNET_SIZE or \
        protocol_size != IPV4_SIZE:
        logging.debug("Se sale del process_arp_frame sin hacer request ni reply")
        pt.print_ARP_header(data, 0)

        return

    # Extraer opcode
    opcode = struct.unpack('!H', data[OPCODE_S:OPCODE_E])[0]

    if opcode == OPCODE_ARP_REQUEST:
        processARPRequest(data, srcMac)
    elif opcode == OPCODE_ARP_REPLY:
        processARPReply(data, srcMac)


def initARP(interface:str) -> int:
    '''
        Nombre: initARP
        Descripción: Esta función construirá inicializará el nivel ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_arp_frame con el Ethertype 0x0806
            -Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
            -Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada. En caso positivo se debe devolver error.
            -Marcar la variable de nivel ARP inicializado a True
    '''
    global myIP,myMAC,arpInitialized, globalLock, requestedIP, awaitingResponse, resolvedMAC

    logging.debug('[FUNC] initARP')

    myIP  = getIP(interface)
    myMAC = getHwAddr(interface)
    arpInitialized = False

    # Registramos al Ethertype 0x0806 (protocolo ARP) la funcion de procesamiento de un paquete
    registerEthCallback(process_arp_frame, ETHERTYPE_ARP)

    # Almacenamos en la tabla cache nuestra IP y nuestra MAC
    with cacheLock:
        cache[myIP] = myMAC

    # Realizar peticiones ARP gratuito para comprobar si nuestra IP ya esta asignada
    request = createARPRequest(myIP)
    logging.debug(f'Request: [{request}]')

    # Indicar que esperamos una respuesta
    with globalLock:
        awaitingResponse = True
        requestedIP = myIP

    # Enviar peticiones
    for _ in range(3):# NOTE  28 = len(request)
        result = sendEthernetFrame(request, len(request), ETHERTYPE_ARP, broadcastAddr)
        if result == -1:
            logging.error('[ERROR]: No se ha podido mandar la petición de ARP gratuito.')
            
            return -1

    NUMERIN_MAGIC_ALONSO = 0.2
    MAX_TRIES = 25
    num_tries = 0

    # Esperar una respuesta. Maximo tiempo de espera: 5 segundos
    while num_tries < MAX_TRIES:
        with globalLock:
            lcl_awaiting_response = awaitingResponse
            lcl_resolved_MAC = resolvedMAC

        # Si nos llega respuesta, entonces alguien más tiene nuestra IP
        if lcl_awaiting_response is False:
            logging.error(f'El dispositivo {pt.MAC_to_str(lcl_resolved_MAC)} ya tiene mi dirección IP')
            return -1

        # Esperamos hasta volver a comprobar
        num_tries += 1
        time.sleep(NUMERIN_MAGIC_ALONSO)


    # Cambiar awaiting response, ya no esperamos respuesta
    if lcl_awaiting_response is True:
        with globalLock:
            awaitingResponse = False
    else:
        logging.error('Alguien más tiene mi dirección IP')
        return -1

    arpInitialized = True

    return 0


def ARPResolution(ip:int) -> bytes:
    '''
        Nombre: ARPResolution
        Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP 
            o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
                -Comprobar si la IP solicitada existe en la caché:
                -Si está en caché devolver la información de la caché
                -Si no está en la caché:
                    -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
                    -Enviar dicha petición
                    -Comprobar si se ha recibido respuesta o no:
                        -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
                        -Si se ha recibido respuesta devolver la dirección MAC
            Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
                -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
                -requestedIP: contiene la IP por la que se está preguntando
                -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
            Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
    '''
    global requestedIP,awaitingResponse,resolvedMAC, cacheLock, cache, globalLock

    logging.debug('[FUNC] ARPResolution')

    if ip == None:
        logging.debug('[ERROR] requestedIP is None')

    with cacheLock:
        mac_cache = cache.get(ip, None)
        if mac_cache != None:
            return mac_cache

    request = createARPRequest(ip)

    with globalLock:
        requestedIP = ip
        awaitingResponse = True
        resolvedMAC = None

    for i in range(3):
        logging.debug(f'Iteracion ARPResolution {i}')
        result = sendEthernetFrame(request, len(request), ETHERTYPE_ARP, broadcastAddr)

        NUMERIN_MAGIC_ALONSO = 0.2
        MAX_TRIES = 25
        num_tries = 0

        while num_tries < MAX_TRIES:
            with globalLock:
                lcl_awaiting_response = awaitingResponse
                lcl_resolved_MAC = resolvedMAC

            if lcl_awaiting_response is True:
                num_tries += 1
                time.sleep(NUMERIN_MAGIC_ALONSO)

            else:
                print(f"resolved mac {lcl_resolved_MAC}")
                return lcl_resolved_MAC
            
    logging.error('Se sale sin hacer la resolucion')

    with globalLock:
        logging.debug(f'awaitingResponse: {awaitingResponse}')
        logging.debug(f'requestedIP: {pt.IP_to_str(requestedIP)}')
        
    return None
