"""
Writer Kcrong

python3 main.py [Interface] [victim ip]
"""

import re
import subprocess
from socket import *
from struct import pack


def get_interface_info(ip=False):
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
            return name, mac_addr

    # 해당 아이피를 가진 인터페이스가 없으면 False 반환
    return False


def packing_ip(ip):
    """
    :param ip: ip to packing big-endian
    :return: packed ip with big-endian
    """
    return pack('!4B', *[int(ip) for ip in ip.split('.')])


def get_my_interface_info(target_ip):
    """
    :param target_ip: victim's ip address
    :return: ip address that connect with victim
    """
    with socket(AF_INET, SOCK_DGRAM) as s:
        s.connect((target_ip, 219))  # 219 is ARP port
        my_ip = s.getsockname()[0]

    name, mac = get_interface_info(my_ip)

    return name, my_ip, mac


def get_victim_mac(target_ip):
    return target_ip


def main():
    # argv check
    # if 3 != len(sys.argv):
    #     print("Usage: python3 %s [victim_ip]\nEx) python3 main.py eth0 192.168.0.4")

    interface = 'wlan0'  # sys.argv[1]
    victim_ip = '192.168.1.1'

    name, ip, mac = get_my_interface_info(victim_ip)
    victim_mac = get_victim_mac(victim_ip)


if __name__ == '__main__':
    main()
