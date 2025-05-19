from pylibpcap.pcap import sniff
import dpkt
import socket
from datetime import datetime

req_por_ip = {}
arquivo_log = open("log_pacotes.txt", "a")

def tcp_flags_para_texto(flags: int) -> str:
    nomes_flags = {
        dpkt.tcp.TH_FIN: "FIN",
        dpkt.tcp.TH_SYN: "SYN",
        dpkt.tcp.TH_RST: "RST",
        dpkt.tcp.TH_PUSH: "PSH",
        dpkt.tcp.TH_ACK: "ACK",
        dpkt.tcp.TH_URG: "URG",
        dpkt.tcp.TH_ECE: "ECE",
        dpkt.tcp.TH_CWR: "CWR",
        dpkt.tcp.TH_NS: "NS", 
    }

    ativadas = [nome for bit, nome in nomes_flags.items() if flags & bit]
    return "|".join(ativadas) if ativadas else "Nenhuma"

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

            print(f"  Flags: {tcp.flags} -  {tcp_flags_para_texto(tcp.flags)}")
            print(f"  Seq: {tcp.seq}  Ack: {tcp.ack}")
            print(f"  Payload len: {len(tcp.data)}")

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

            elif dport == 25:  
                print(f"\n[SMTP] {datetime.fromtimestamp(t)}")
                print(f"  {ip_src}:{tcp.sport} → {ip_dst}:{tcp.dport}")
                
                try:
                    smtp_data = tcp.data.decode("utf-8", errors="ignore")
                    print(f"  Conteúdo SMTP: {smtp_data}")
                except Exception as e:
                    smtp_data = tcp.data.hex()
                    print(f"  Conteúdo SMTP (hex): {smtp_data} (erro: {e})")
                
                arquivo_log.write(f"{datetime.fromtimestamp(t)} | [SMTP] {ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport} | Conteúdo: {smtp_data}\n")
                arquivo_log.flush()
            else:
                print(f"\n[TCP] {datetime.fromtimestamp(t)}")
                print(f"  {ip_src}:{tcp.sport} → {ip_dst}:{tcp.dport}")
                arquivo_log.write(f"{datetime.fromtimestamp(t)} | [TCP] {ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport}\n")
                arquivo_log.flush()

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            data = udp.data

            print(f"\n[UDP] {datetime.fromtimestamp(t)}")
            print(f"  {ip_src}:{udp.sport} → {ip_dst}:{udp.dport}")
            print(f"  UDP Length: {udp.ulen} bytes")
            print(f"  UDP Checksum: {udp.sum}")
            print(f"  Tamanho do payload: {len(data)} bytes")

            conteudo_str = ""

            # Verifica se é DNS (porta 53)
            if udp.sport == 53 or udp.dport == 53:
                try:
                    dns = dpkt.dns.DNS(data)
                    if dns.qr == dpkt.dns.DNS_Q:  # Query
                        perguntas = ", ".join(q.name for q in dns.qd)
                        print(f"  [DNS] Consulta para: {perguntas}")
                        conteudo_str = f"[DNS Query] {perguntas}"
                    elif dns.qr == dpkt.dns.DNS_R:  # Resposta
                        respostas = ", ".join(rr.name for rr in dns.an)
                        print(f"  [DNS] Resposta para: {respostas}")
                        conteudo_str = f"[DNS Response] {respostas}"
                    else:
                        conteudo_str = "[DNS] Pacote DNS não identificado"
                except Exception as e:
                    print(f"  [DNS] Erro ao decodificar DNS: {e}")
                    conteudo_str = "[DNS] Erro ao decodificar"
            else:
                if data:
                    try:
                        texto = data.decode("utf-8", errors="ignore")
                        print(f"  Conteúdo (UTF-8): {texto}")
                        conteudo_str = texto.replace("\n", "\\n").replace("\r", "\\r")
                    except Exception:
                        conteudo_str = data.hex()
                        print(f"  Conteúdo (hex): {conteudo_str}")
                else:
                    conteudo_str = "[sem dados]"
            
            arquivo_log.write(conteudo_str)
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
    interface = "enp42s0"
    iniciar_sniffer(interface)
