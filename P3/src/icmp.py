'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1


ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

############################
# INDICES DE CABECERA ICMP #
############################
#S = Start
#E = End 
#I = Index
ICMP_TYPE_I = 0 #1 byte
ICMP_CODE_I = 1 #1 byte
ICMP_CHKSUM_S = 2 #2 bytes 
ICMP_CHKSUM_E = 3 + 1
ICMP_IDENTIFIER_S = 4 #2 bytes
ICMP_IDENTIFIER_E = 5 + 1
ICMP_SEQ_NUMBER_S = 6 #2 bytes
ICMP_SEQ_NUMBER_E = 7 + 1


timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header: pcap_pkthdr,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
    '''
    logging.debug("[FUNC] process_ICMP_message")
    icmp_cksum = struct.unpack('H', data[ICMP_CHKSUM_S:ICMP_CHKSUM_E])[0]
    #logging.debug(f'Checksum paquete: {data[ICMP_CHKSUM_S:ICMP_CHKSUM_E]}')
    #logging.debug(f'Checksum calculo: {chksum(data_orig)}')
    # Comprobacion de checksum
    data_orig = data[0:CHECKSUM_S] + struct.pack('!H', 0) + data[CHECKSUM_E:]
    if icmp_cksum != chksum(data_orig):
        logging.debug('Checksum does not match')
        return

    echo_type = data[ICMP_TYPE_I]
    code = data[ICMP_CODE_I]
    identifier = data[ICMP_IDENTIFIER_S:ICMP_IDENTIFIER_E]
    seq_number = data[ICMP_SEQ_NUMBER_S:ICMP_SEQ_NUMBER_E]


    type_as_str = 'request' if echo_type == ICMP_ECHO_REQUEST_TYPE else 'reply' if echo_type == ICMP_ECHO_REPLY_TYPE else 'unknown'
    logging.debug( 'Datagrama ICMP recibido:')
    logging.debug(f'   - Type: {type} ({type_as_str})')
    logging.debug(f'   - Code: {code}')


    # Process request
    if type == ICMP_ECHO_REQUEST_TYPE:
        sendICMPMessage(data[ICMP_SEQ_NUMBER_E:], ICMP_ECHO_REPLY_TYPE, 0, identifier, seq_number, srcIp)
    # Process reply
    elif type == ICMP_ECHO_REPLY_TYPE:
        key = srcIp + identifier + seq_number

        with timeLock:
            send_time: float = icmp_send_times.get(key, None)

        if send_time is not None:
            diff_time = (header.ts.tv_sec + header.ts.tv_usec*0.000001) - send_time

            logging.debug(f'   - RTT: {diff_time} sec')


def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
    '''
    logging.debug("[FUNC] sendICMPMessage")
    if type != ICMP_ECHO_REQUEST_TYPE and type != ICMP_ECHO_REPLY_TYPE:
        return False

    icmp_message = bytes()

    icmp_message += struct.pack('!B', type)
    icmp_message += struct.pack('!B', code)
    icmp_message += struct.pack('!H', 0)
    icmp_message += struct.pack('!H', icmp_id)
    icmp_message += struct.pack('!H', icmp_seqnum)
    icmp_message += data

    icmp_message[ICMP_CHKSUM_S:ICMP_CHKSUM_E] = struct.pack('H', chksum(icmp_message))

    if type == ICMP_ECHO_REQUEST_TYPE:
        key = dstIP + icmp_id + icmp_seqnum
        send_time = time.time()

        with timeLock:
            icmp_send_times[key] = send_time

    return sendIPDatagram(dstIP, data, ICMP_PROTO)

   
def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
    '''
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)
