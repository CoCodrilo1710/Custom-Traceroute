import socket
import struct
import requests
import ipaddress
from collections import Counter


def traceroute(HostName):
    dest_addr = socket.gethostbyname(HostName)
    print(f"Traceroute {HostName}: ")
    print()

    # For Linux
    scriu = open("/root/Desktop/results/result__" + HostName + ".txt", "w")
    # For Windows
    # scriu = open("result__" + HostName + ".txt", "w")

    scriu.write(f"Traceroute {HostName}: \n")
    scriu.write("\n")
    Max = 64
    TTL = 1
    port = 33434
    listaIp = []

    while True:
        udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
        udp_send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, TTL)

        # RAW socket for reading ICMP responses
        icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_recv_socket.settimeout(3)
        icmp_recv_socket.bind(("", 33434))  # 33434 is the default port used for traceroute

        packet = b"traceroute"  # Convert string to bytes
        udp_send_sock.sendto(packet, (dest_addr, port))

        try:
            if TTL >= Max:
                break
            Data, Router_addr = icmp_recv_socket.recvfrom(1024)  # Data contains the ICMP packet, Router_addr contains the responding router's address
            print(f"{Router_addr[0]} TTL: [{TTL}]")
            scriu.write(f"{Router_addr[0]} TTL: [{TTL}] \n")
            listaIp.append(Router_addr[0])
            if Router_addr[0] == dest_addr or TTL >= Max:  # Stop if we have reached the destination or exceeded the maximum TTL
                break

        except Exception as e:  # If no response from the current router, move to the next TTL
            pass
        finally:
            icmp_recv_socket.close()
            udp_send_sock.close()

        TTL = TTL + 1

    fake_HTTP_header = {
        'referer': 'https://api.ip2loc.com/',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
    }
    tari = []
    orase = []
    regiuni = []

    for ip in listaIp:
        response = requests.get('https://api.ip2loc.com/3JlbBXgK3q8RRRPBwpf8H9wh5v4ScMgr/' + ip, headers=fake_HTTP_header)
        data = response.json()
        tari.append(data['location']['country']['name'])
        regiuni.append(data['location']['country']['subdivision'])
        orase.append(data['location']['city'])

    print('----------------')
    print('----------------')
    print()
    print('IP Route: ')
    scriu.write('----------------\n')
    scriu.write('----------------\n')
    scriu.write('IP Route: \n')
    for i in range(len(listaIp) - 1):
        print(listaIp[i] + ' --->', end='')
        scriu.write(listaIp[i] + ' --->')
    print(listaIp[len(listaIp) - 1])
    scriu.write(listaIp[len(listaIp) - 1] + '\n')

    print('----------------')
    print('----------------')
    print('Sanitized IP Route: ')
    scriu.write('---------------- \n')
    scriu.write('---------------- \n')
    scriu.write('Sanitized IP Route: \n')

    for i in range(len(listaIp) - 1):
        if ipaddress.ip_address(listaIp[i]).is_private:
            print('INTERNAL IP --->', end='')
            scriu.write('INTERNAL IP --->')
        else:
            print(listaIp[i] + ' --->', end='')
            scriu.write(listaIp[i] + ' --->')
    print(listaIp[len(listaIp) - 1])
    scriu.write(listaIp[len(listaIp) - 1] + '\n')

    print('----------------')
    print('----------------')
    scriu.write('---------------- \n')
    scriu.write('---------------- \n')

    print('Geographic Route: \n \n')
    scriu.write('Geographic Route: \n \n')

    for i in range(len(tari) - 1):
        if ipaddress.ip_address(listaIp[i]).is_private:
            print('Unknown location, Internal IP! ----->', end='')
            scriu.write('Unknown location, Internal IP! ----->')
        else:
            if tari[i] is None:
                print('Unknown location, Reserved IP! ----->', end='')
                scriu.write('Unknown location, Reserved IP! ----->')
            else:
                if orase[i] is not None:
                    print(f"{orase[i]}, {regiuni[i]}, {tari[i]} -----> ", end='')
                    scriu.write(f"{orase[i]}, {regiuni[i]}, {tari[i]} -----> ")
                else:
                    print(f"Unknown city, Unknown region, {tari[i]} -----> ", end='')
                    scriu.write(f"Unknown city, Unknown region, {tari[i]} -----> ")
        if i % 2 == 0 and i + 2 != len(tari) and i != 0:
            print()
            scriu.write('\n')

    if ipaddress.ip_address(listaIp[len(listaIp) - 1]).is_private:
        print('Unknown location, Internal IP!')
        scriu.write('Unknown location, Internal IP! \n')
    else:
        if tari[-1] is None:
            print('Unknown location, Reserved IP! ', end='')
            scriu.write('Unknown location, Reserved IP! ')
        else:
            if orase[-1] is not None:
                print(f"{orase[-1]}, {regiuni[-1]}, {tari[-1]}  ", end='')
                scriu.write(f"{orase[-1]}, {regiuni[-1]}, {tari[-1]}  ")
            else:
                print(f"Unknown city, Unknown region, {tari[-1]}  ", end='')
                scriu.write(f"Unknown city, Unknown region, {tari[-1]}  ")

    print()
    print('----------------')
    print('Top most frequent cities in traceroute: ')
    print()
    scriu.write('\n')
    scriu.write('---------------- \n')
    scriu.write('Top most frequent cities in traceroute: \n')
    scriu.write('\n')

    topOrase = Counter(orase).most_common(10)
    i, k = 0, 1
    while i < len(topOrase):
        if topOrase[i][0] is not None:
            print(f"{k}. {topOrase[i][0]}")
            scriu.write(f"{k}. {topOrase[i][0]} \n")
            k = k + 1
        i += 1

    print()
    print('----------------')
    print('Top most frequent countries in traceroute: ')
    print()
    scriu.write('\n')
    scriu.write('---------------- \n')
    scriu.write('Top most frequent countries in traceroute: \n')
    scriu.write('\n')

    topTari = Counter(tari).most_common(10)
    i, k = 0, 1
    while i < len(topTari):
        if topTari[i][0] is not None and topTari[i][0] != 'Unknown Country':
            print(f"{k}. {topTari[i][0]}")
            scriu.write(f"{k}. {topTari[i][0]} \n")
            k = k + 1
        i += 1
    print()
    print()
    print()
    scriu.close()


if __name__ == '__main__':
    print('Choose the desired option: ')
    print('1. Traceroute DNS Google')
    print('2. Traceroute Facebook')
    print('3. Traceroute for a specific site / IP')
    print('4. Write File for subpoint 3 (You will need to provide a file that contains a single IP or site on each line)')

    option = int(input())

    if option == 1:
        traceroute("8.8.8.8")
    elif option == 2:
        traceroute("www.facebook.com")
    elif option == 3:
        site = input('Enter the site / IP: ')
        traceroute(site)
    elif option == 4:
        filename = input('Enter the file name: ')
        f = open(filename, 'r')
        print()
        for line in f:
            traceroute(line.strip())
        f.close()
