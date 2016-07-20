"""
Writer Kcrong

python3 main.py [victim ip]
"""

import re
import subprocess
import binascii
from socket import *

from packet_header_define import *
from struct import unpack


class ARP:
    def __init__(self, victim):
        self.target_ip = victim
        self.name, self.ip, self.mac = self._get_my_interface_info()
        self.target_mac = self._get_victim_mac()

    def _get_my_interface_info(self):
        """
        target_ip 와 연결된 인터페이스의 정보를 가져옴

        :return: ip address that connect with victim
        """
        with socket(AF_INET, SOCK_DGRAM) as s:
            s.connect((self.target_ip, 219))  # 219 is ARP port
            my_ip = s.getsockname()[0]

        name, mac = self._get_interface_info(my_ip)

        return name, my_ip, mac

    @staticmethod
    def _get_interface_info(ip):
        """
        아이피를 인자로 받아 해당 아이피를 가진 인터페이스의 이름을 반환

        :param ip: ip to find interface
        :return: interface info that has ip
        """

        name_pattern = "^(\w+)\s"
        # mac_addr_pattern = ".*?HWaddr[ ]([0-9A-Fa-f:]{17})"
        ip_addr_pattern = ".*?\n\s+inet[ ]addr:((?:\d+\.){3}\d+)"
        #       pattern = re.compile("".join((name_pattern, mac_addr_pattern, ip_addr_pattern)),
        pattern = re.compile("".join((name_pattern, ip_addr_pattern)),
                             flags=re.MULTILINE)

        # 정규식을 이용해 ifconfig 명령어 결과를 파싱
        ifconfig_result = subprocess.check_output("ifconfig").decode()
        interfaces = pattern.findall(ifconfig_result)

        for name, ip_addr in interfaces:
            if ip == ip_addr:
                # 구한 Interface 이름을 이용해 MAC 주소를 raw socket 을 이용해 convert 된 값을 가져옴
                with socket(AF_PACKET, SOCK_RAW, SOCK_RAW) as s:
                    s.bind((name, SOCK_RAW))
                    return name, s.getsockname()[4]

        # 해당 아이피를 가진 인터페이스가 없으면 False 반환
        return False

    @staticmethod
    def _packing_ip(ip):
        """
        우리가 사용하는 String Format ( "123.123.123.123" ) 을 Big-endian 으로 packing 해주는 함수

        :param ip: ip to packing big-endian
        :return: packed ip with big-endian
        """
        return pack('!4B', *[int(ip) for ip in ip.split('.')])

    def send_arp(self, send_type):
        """
        send_type 에 따라 target_ip에 arp 패킷을 전송합니다.

        :param send_type: Request 나 Receive 에 대한 Opcode.
        :return: None. Just send packet
        """

        s = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)
        s.bind((self.name, SOCK_RAW))

        packed_sender_mac = s.getsockname()[4]
        packed_sender_ip = self._packing_ip(self.ip)
        packed_target_ip = self._packing_ip(self.target_ip)

        packet_frame = [
            # # Ethernet Frame
            # Dest MAC
            BROADCAST_MASK,

            # Src MAC
            packed_sender_mac,

            # Protocol type
            ARP_TYPE_ETHERNET_PROTOCOL,

            # ############################################3
            # # ARP
            ARP_PROTOCOL_TYPE,

            # ARP type
            send_type,

            # Sender MAC addr
            packed_sender_mac,

            # Sender IP addr
            packed_sender_ip,

            # Broadcast? Unicast?
            ZERO_MASK,  # i just want unicast

            # Target IP addr
            packed_target_ip

            # Done!
        ]

        # GOGOGO!
        # Just byte code
        s.send(b''.join(packet_frame))

    def _receive_arp(self, target_ip):
        """
        target_ip 의 Reply packet 을 확인하여 mac 주소를 반환합니다.
        :param target_ip: target's ip address
        :return: target's mac address
        """

        # Before waiting ARP-REPLY, Send REQUEST
        self.send_arp(ARP_REQUEST_OP)

        s = socket(AF_PACKET, SOCK_RAW, htons(0x0003))

        while True:
            packet = s.recvfrom(2048)

            ethernet_unpacked = unpack("!6s6s2s", packet[0][0:14])

            arp_header = packet[0][14:42]
            arp_unpacked = unpack("2s2s1s1s2s6s4s6s4s", arp_header)

            source_ip = inet_ntoa(arp_unpacked[6])

            if ethernet_unpacked[2] != ARP_TYPE_ETHERNET_PROTOCOL:
                continue

            elif source_ip == target_ip:
                print("Target MAC detected: %s" % binascii.hexlify(arp_unpacked[5]))
                return arp_unpacked[5]

    def _get_victim_mac(self):
        """
        target_ip 에게 ARP Request 를 보내 MAC 주소를 받아옴

        :return: victim's mac address
        """
        return self._receive_arp(self.target_ip)


def main():



    victim_ip = '192.168.1.1'
    arp = ARP(victim_ip)

    arp.send_arp(ARP_REQUEST_OP)


if __name__ == '__main__':
    main()
