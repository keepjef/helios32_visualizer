import sys
import dpkt
from collections import Counter

def analyze_pcap(filepath):
    print(f"=== Анализ файла: {filepath} ===")
    with open(filepath, 'rb') as f:
        try:
            reader = dpkt.pcap.Reader(f)
            print(f"Формат: PCAP, Datalink: {reader.datalink()}")
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)
            print(f"Формат: PCAPNG")

        ports = Counter()
        lengths = Counter()

        for i, (ts, buf) in enumerate(reader):
            if i >= 20000: 
                break # Анализируем только первые 20 000 пакетов для скорости
            
            lengths[len(buf)] += 1
            
            # Универсальный перебор форматов (Ethernet, Linux SLL, macOS Loopback)
            ip = None
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if hasattr(eth, 'data') and hasattr(eth.data, 'p'): ip = eth.data
            except: pass
            
            if not ip:
                try:
                    sll = dpkt.sll.SLL(buf)
                    if hasattr(sll, 'data') and hasattr(sll.data, 'p'): ip = sll.data
                except: pass
            
            if not ip:
                try:
                    loop = dpkt.ip.IP(buf[4:])
                    if hasattr(loop, 'p'): ip = loop
                except: pass

            # Протокол 17 = UDP (работает и для IPv4, и для IPv6)
            if ip and ip.p == 17:
                try:
                    udp = ip.data
                    ports[udp.dport] += 1
                except: pass

        print("\nТоп 5 размеров пакетов (в байтах):", lengths.most_common(5))
        if not ports:
            print("UDP пакеты НЕ НАЙДЕНЫ. Либо это TCP, либо файл зашифрован/поврежден.")
        else:
            print("Топ UDP портов (Именно они нужны нам):", ports.most_common(5))

# Подставь сюда путь к своему pcap файлу
analyze_pcap("/Users/keepjef/my_projects/lidar/lidars-dump.pcap")