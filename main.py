"""
Writer Kcrong

python3 main.py [Interface] [victim ip]
"""

import re
import subprocess
from socket import *
from struct import pack


def get_interfaces(ip=False):
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
        if ip_addr == ip:
            return name

    # 해당 아이피를 가진 인터페이스가 없으면 False 반환
    return False


def packing_ip(ip):
    """
    :param ip: ip to packing big-endian
    :return: packed ip with big-endian
    """
    return pack('!4B', *[int(ip) for ip in ip.split('.')])


def get_my_ip(target_ip):
    """
    :param target_ip: victim's ip address
    :return: ip address that connect with victim
    """
    with socket(AF_INET, SOCK_DGRAM) as s:
        s.connect((target_ip, 219))  # 219 is ARP port
        return s.getsockname()[0]


def get_my_mac():
    """
    Get my mac address using raw socket
    :return: My mac address
    """

    with socket(AF_PACKET, SOCK_RAW, SOCK_RAW) as s:
        s.bind(())


def get_victim_mac(target_ip):
    return target_ip


def main():
    # argv check
    # if 3 != len(sys.argv):
    #     print("Usage: python3 %s [interface] [victim_ip]\nEx) python3 main.py eth0 192.168.0.4")

    interface = 'wlan0'  # sys.argv[1]
    victim_ip = '192.168.1.1'

    my_ip = get_my_ip(victim_ip)
    victim_mac = get_victim_mac(victim_ip)


if __name__ == '__main__':
    main()
