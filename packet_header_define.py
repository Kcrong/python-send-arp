from struct import pack

ZERO_MAC = pack('!6B', *(0x00,) * 6)
BROADCAST_MAC = pack('!6B', *(0xFF,) * 6)
ARP_REQUEST_OP = pack('!H', 0x0001)
ARP_REPLY_OP = pack('!H', 0x0002)