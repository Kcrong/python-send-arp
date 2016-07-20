"""
Writer Kcrong

python3 main.py [victim ip]
"""

import re
import subprocess
from socket import *

from packet_header_define import *


class ARP:
    def __init__(self, victim):
        self.target_ip = victim
        self.name, self.ip, self.mac = self._get_my_interface_info()

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
        :return: interface name that has ip
        """

        name_pattern = "^(\w+)\s"
        mac_addr_pattern = ".*?HWaddr[ ]([0-9A-Fa-f:]{17})"
        ip_addr_pattern = ".*?\n\s+inet[ ]addr:((?:\d+\.){3}\d+)"
        pattern = re.compile("".join((name_pattern, mac_addr_pattern, ip_addr_pattern)),
                             flags=re.MULTILINE)

        # 정규식을 이용해 ifconfig 명령어 결과를 파싱
        ifconfig_result = subprocess.check_output("ifconfig").decode()
        interfaces = pattern.findall(ifconfig_result)

        for name, mac_addr, ip_addr in interfaces:
            if ip == ip_addr:
                return name, mac_addr

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
            BROADCAST_MAC,

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
            ZERO_MAC,  # i just want unicast

            # Target IP addr
            packed_target_ip

            # Done!
        ]

        # GOGOGO!
        # Just byte code
        s.send(b''.join(packet_frame))

    def _get_victim_mac(self):
        """
        target_ip 에게 ARP Request 를 보내 MAC 주소를 받아옴

        :return: victim's mac address
        """
        return self.target_ip


def main():
    # argv check
    # if 3 != len(sys.argv):
    #     print("Usage: python3 %s [victim_ip]\nEx) python3 main.py eth0 192.168.0.4")

    victim_ip = '192.168.1.1'
    arp = ARP(victim_ip)

    arp.send_arp(ARP_REQUEST_OP)


if __name__ == '__main__':
    main()
