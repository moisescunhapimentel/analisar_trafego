from pylibpcap.pcap import sniff
import dpkt
import socket
from datetime import datetime

req_por_ip = {}
arquivo_log = open("log_pacotes.txt", "a")


def tratar_pacote(plen, t, buf):
    try:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            return

        ip = eth.data
        ip_src = socket.inet_ntoa(ip.src)
        ip_dst = socket.inet_ntoa(ip.dst)

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            dport = tcp.dport

            if dport == 80:
                if len(tcp.data) == 0:
                    return
                try:
                    http = dpkt.http.Request(tcp.data)
                    host = http.headers.get("host", "N/D")
                    user_agent = http.headers.get("user-agent", "N/D")
                    req_por_ip[ip_src] = req_por_ip.get(ip_src, 0) + 1

                    print(f"\n[HTTP] {datetime.fromtimestamp(t)}")
                    print(f"  {ip_src} → {ip_dst}")
                    print(f"  Host: {host}")
                    print(f"  User-Agent: {user_agent}")

                    arquivo_log.write(f"{datetime.fromtimestamp(t)} | [HTTP] {ip_src} -> {ip_dst} | Host: {host} | UA: {user_agent}\n")
                    arquivo_log.flush()

                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    pass

            elif dport == 443:
                print(f"\n[HTTPS] {datetime.fromtimestamp(t)}")
                print(f"  {ip_src} → {ip_dst}")
                arquivo_log.write(f"{datetime.fromtimestamp(t)} | [HTTPS] {ip_src} -> {ip_dst}\n")
                arquivo_log.flush()

            else:
                print(f"\n[TCP] {datetime.fromtimestamp(t)}")
                print(f"  {ip_src}:{tcp.sport} → {ip_dst}:{tcp.dport}")
                arquivo_log.write(f"{datetime.fromtimestamp(t)} | [TCP] {ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport}\n")
                arquivo_log.flush()

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data

            print(f"\n[UDP] {datetime.fromtimestamp(t)}")
            print(f"  {ip_src}:{udp.sport} → {ip_dst}:{udp.dport}")
            arquivo_log.write(f"{datetime.fromtimestamp(t)} | [UDP] {ip_src}:{udp.sport} -> {ip_dst}:{udp.dport}\n")
            arquivo_log.flush()

        else:
            print(f"\n[OUTRO] {datetime.fromtimestamp(t)}")
            print(f"  {ip_src} → {ip_dst}")
            arquivo_log.write(f"{datetime.fromtimestamp(t)} | [OUTRO] {ip_src} -> {ip_dst}\n")
            arquivo_log.flush()



    except Exception as e:
        print(f"Erro ao processar pacote: {e}")


def iniciar_sniffer(interface):
    print(f"🔌 Capturando na interface: {interface}")
    while True:
        try:
            for plen, t, buf in sniff(interface, filters="", count=-1, promisc=1):
                tratar_pacote(plen, t, buf)
        except Exception as e:
            print(f"Erro na captura de pacotes: {e}")


if __name__ == "__main__":
    interface = ""
    iniciar_sniffer(interface)
