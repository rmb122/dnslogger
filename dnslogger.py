import time
import socket
import traceback

# DNSQuery class from http://code.activestate.com/recipes/491264-mini-fake-dns-server/
def analysisDnsQuery(data):
    domain = b''
    tipo = (data[2] >> 3) & 15  # Opcode bits
    if tipo == 0:  # Standard query
        ini = 12
        lon = data[ini]
        while lon != 0:
            domain += data[ini + 1:ini + lon + 1] + b'.'
            ini += lon + 1
            lon = data[ini]
        reqType = data[ini + 2]
    else: # Not a standard query
        domain, reqType = "", 0x0
    
    return domain, reqType


def getDnsResponseA(data):
    packet = bytearray()
    packet += data[:2] + b'\x81\x80'
    packet += data[4:6] + data[4:6] + b'\x00\x00\x00\x00'  # Questions and Answers Counts
    packet += data[12:]  # Original Domain Name Question
    packet += b'\xc0\x0c'  # Pointer to domain name
    packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # Response type, ttl and resource data length -> 4 bytes
    packet += b'\x7f\x00\x00\x01'  # 4bytes of IP, 127.0.0.1
    return packet


def getDnsResponseAAAA(data):
    packet = bytearray()
    packet += data[:2] + b'\x81\x80'
    packet += data[4:6] + data[4:6] + b'\x00\x00\x00\x00'  # Questions and Answers Counts
    packet += data[12:]  # Original Domain Name Question
    packet += b'\xc0\x0c'  # Pointer to domain name
    packet += b'\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10'  # Response type, ttl and resource data length -> 4 bytes
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'  # 16 bytes of IPv6, ::1
    return packet


sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
sck.bind(('0.0.0.0', 53))


while True:
    try:
        request, addr = sck.recvfrom(1024)
        domain, reqType = analysisDnsQuery(request)
        if reqType == 0x01:
            print(f"[{time.asctime()[11:19]}] [{domain.decode()}] from [{addr[0]}] with type [A]")
            # 想要回复请求的话, 去掉下面的两个注释就可以了
            # response = getDnsResponseA(request)
            # sck.sendto(response, addr)
        elif reqType == 0x1c:
            print(f"[{time.asctime()[11:19]}] [{domain.decode()}] from [{addr[0]}] with type [AAAA]")
            # response = getDnsResponseAAAA(request)
            # sck.sendto(response, addr)
        else:
            print(f"[{time.asctime()[11:19]}] [{domain.decode()}] from [{addr[0]}] with unknown type [{hex(reqType)}]")
    except KeyboardInterrupt:
        sck.close()
        break
    except Exception:
        traceback.print_exc()
