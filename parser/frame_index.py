import os
import numpy as np
import dpkt

class FrameIndex:
    def __init__(self, pcap_path, port=2368):
        self.pcap_path = pcap_path
        self.port = int(port)
        # Сохраняем порт в названии кэша, чтобы они не пересекались
        self.index_path = pcap_path + f'_{self.port}.index.npy'
        self.frame_packets = []

    def load_or_build(self):
        if os.path.exists(self.index_path):
            print(f"Загрузка кэша из {self.index_path}...")
            self.frame_packets = np.load(self.index_path).tolist()
            return

        self.build_index()
        np.save(self.index_path, np.array(self.frame_packets))

    def _get_udp_payload(self, buf):
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

        if ip and ip.p == 17:
            try:
                udp = ip.data
                if udp.dport == self.port:
                    return udp.data
            except: pass
        return None

    def build_index(self):
        print(f"Построение индекса кадров (Порт: {self.port})... Это займет пару минут.")
        self.frame_packets = [0]
        last_azimuth = -1
        valid_udp_count = 0
        
        with open(self.pcap_path, 'rb', buffering=16 * 1024 * 1024) as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)

            packet_idx = 0
            for ts, buf in reader:
                payload = self._get_udp_payload(buf)
                
                if payload and len(payload) >= 142:
                    valid_udp_count += 1
                    azimuth = ((payload[44] << 8) | payload[45]) / 100.0
                    
                    if last_azimuth != -1 and abs(azimuth - last_azimuth) > 90:
                        self.frame_packets.append(packet_idx)
                    
                    last_azimuth = azimuth
                packet_idx += 1
                
        print(f"Прочитано LiDAR пакетов: {valid_udp_count}")
        print(f"Индекс построен! Найдено кадров по углу: {len(self.frame_packets)}")

    def frame_count(self):
        return len(self.frame_packets)