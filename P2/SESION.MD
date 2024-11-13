# Viernes 25 de octubre

### Inicialización del nivel ARP

Tenemos que inicializar el nivel ARP. Haremos un ARP gratuito para comprobar si nuestra IP ya está implementada. Para ello, debemos completar el método `initARP` las siguientes tareas:
1. Registrar la función del callback `process_arp_frame` (descrita más adelante) con el Ethertype 0x0806.
2. Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada en la tabla caché temporal.
3. Realizar tres peticiones ARP Gratuito y comprobar si la IP propia ya está asignada
4. Marcar la variable de nivel ARP inicializado a True.

Tarea 1:
* `registerEthCallback`
* `process_arp_frame`
    * `processARPRequest`: **TODO**
    * `processARPReply`: **TODO**
Tarea 3:
* `createARPRequest`
* `sendEthernetFrame`