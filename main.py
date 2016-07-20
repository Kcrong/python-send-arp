"""
Writer Kcrong

python3 main.py [victim ip]
"""

import re
import subprocess
from socket import *
from struct import pack

ARP_REQUEST = 0
ARP_RECEIVE = 1


class ARP:
    def __init__(self, victim):
        self.target_ip = victim
        self.name, self.mac, self.ip = self._get_my_interface_info()

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

    def _get_interface_info(self, ip=False):
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
            if ip and self.ip == ip_addr:
                return name, mac_addr

        # 해당 아이피를 가진 인터페이스가 없으면 False 반환
        return False

    @staticmethod
    def packing_ip(ip):
        """
        우리가 사용하는 String Format ( "123.123.123.123" ) 을 Big-endian 으로 packing 해주는 함수

        :param ip: ip to packing big-endian
        :return: packed ip with big-endian
        """
        return pack('!4B', *[int(ip) for ip in ip.split('.')])

    def send_arp(self, send_type):
        """
        send_type 에 따라 target_ip에 arp 패킷을 전송합니다.

        :param send_type: ARP_REQUEST 혹은 ARP_RECEIVE 중 하나. arp 패킷의 종류
        :return: None. Just send packet
        """

        s = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)

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

    arp.send_arp(ARP_REQUEST)


if __name__ == '__main__':
    main()
