import struct


def MAC_to_str(mac: bytes) -> str:
    mac6 = struct.unpack('B', mac[0:1])[0]
    mac5 = struct.unpack('B', mac[1:2])[0]
    mac4 = struct.unpack('B', mac[2:3])[0]
    mac3 = struct.unpack('B', mac[3:4])[0]
    mac2 = struct.unpack('B', mac[4:5])[0]
    mac1 = struct.unpack('B', mac[5:6])[0]

    return f'{mac6:02x}.{mac5:02x}.{mac4:02x}.{mac3:02x}.{mac2:02x}.{mac1:02x}'


def IP_to_str(ip: int) -> str:
    ip4 = (ip & 0x000000FF) >> 0x00
    ip3 = (ip & 0x0000FF00) >> 0x08
    ip2 = (ip & 0x00FF0000) >> 0x10
    ip1 = (ip & 0xFF000000) >> 0x18

    return f'{ip1}.{ip2}.{ip3}.{ip4}'



def print_ethernet_header(data: bytes, ident: int = 0):
	print("\t"*ident, 'ETHERNET FRAME:')
	ident += 1
	print("\t"*ident, 'Dest MAC:  ', MAC_to_str(data[0:6]))
	print("\t"*ident, 'Orig MAC:  ', MAC_to_str(data[6:12]))
	print("\t"*ident, 'Ethertype: ', f'{ struct.unpack("!H", data[12:14])[0] :04x}')


def print_ethernet_message(data: bytes, ident: int = 0):
	print("\t"*ident, 'MESSAGE:')
	ident += 1
	print("\t"*ident, f'[{data[18:].decode()}]')


def print_ARP_header(data: bytes, ident: int = 0):
	print("\t"*ident, 'ARP REPLY:')
	ident += 1
	print("\t"*ident, 'Hardware Type:         ', hex(struct.unpack('!H', data[0:2])[0]))
	print("\t"*ident, 'Protocol Type:         ', hex(struct.unpack('!H', data[2:4])[0]))
	print("\t"*ident, 'Ethernet Address Size: ', hex(struct.unpack('!B', data[4:5])[0]))
	print("\t"*ident, 'Protocol Address Size: ', hex(struct.unpack('!B', data[5:6])[0]))
	print("\t"*ident, 'OP Code:               ', hex(struct.unpack('!H', data[6:8])[0]))
	print("\t"*ident, 'Orig MAC:              ', MAC_to_str(data[8:14]))
	print("\t"*ident, 'Orig IP:               ', IP_to_str(struct.unpack('!I', data[14:18])[0]))
	print("\t"*ident, 'Dest MAC:              ', MAC_to_str(data[18:24]))
	print("\t"*ident, 'Dest IP:               ', IP_to_str(struct.unpack('!I', data[24:28])[0]))

