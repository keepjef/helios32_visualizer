import struct
import numpy as np
import dpkt

VERTICAL_ANGLES = np.radians([
    15,13,11,9,7,5.5,4,2.67,
    1.33,0,-1.33,-2.67,-4,-5.33,
    -6.67,-8,-10,-16,-13,-19,
    -22,-28,-25,-31,-34,-37,
    -40,-43,-46,-49,-52,-55
])

class HeliosParser:
    def __init__(self, pcap_path, frame_index, port=2368):
        self.pcap_path = pcap_path
        self.frame_index = frame_index
        self.port = int(port)
        
        self.cos_v = np.cos(VERTICAL_ANGLES).astype(np.float32)
        self.sin_v = np.sin(VERTICAL_ANGLES).astype(np.float32)

        self.f = open(self.pcap_path, 'rb', buffering=16 * 1024 * 1024)
        self._init_reader()

        self.current_packet_idx = 0
        self.cached_packet = None

    def _init_reader(self):
        self.f.seek(0)
        try:
            self.reader = dpkt.pcap.Reader(self.f)
        except ValueError:
            self.f.seek(0)
            self.reader = dpkt.pcapng.Reader(self.f)

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

    def load_frame(self, frame_id):
        start_packet = self.frame_index.frame_packets[frame_id]
        
        if frame_id + 1 < len(self.frame_index.frame_packets):
            end_packet = self.frame_index.frame_packets[frame_id + 1]
        else:
            end_packet = start_packet + 5000

        if start_packet < self.current_packet_idx:
            if self.cached_packet is not None and self.cached_packet[0] == start_packet:
                pass
            else:
                self._init_reader()
                self.current_packet_idx = 0
                self.cached_packet = None

        frame_payloads = []

        if self.cached_packet is not None:
            idx, ts, buf = self.cached_packet
            if start_packet <= idx < end_packet:
                self._process_packet_to_list(buf, frame_payloads)
                self.cached_packet = None
            elif idx >= end_packet:
                pass

        while self.current_packet_idx < end_packet:
            try:
                ts, buf = next(self.reader)
            except StopIteration:
                break

            idx = self.current_packet_idx
            self.current_packet_idx += 1

            if idx < start_packet: continue

            if idx == end_packet:
                self.cached_packet = (idx, ts, buf)
                break

            self._process_packet_to_list(buf, frame_payloads)

        return self._parse_payloads_numpy(frame_payloads)

    def _process_packet_to_list(self, buf, payloads_list):
        payload = self._get_udp_payload(buf)
        if payload and len(payload) >= 142:
            max_blocks = (len(payload) - 42) // 100
            if max_blocks > 12: max_blocks = 12
            if max_blocks > 0:
                payloads_list.append(payload[42 : 42 + max_blocks * 100])

    def _parse_payloads_numpy(self, frame_payloads):
        if not frame_payloads: return np.zeros((0, 4), dtype=np.float32)

        blocks_data = b''.join(frame_payloads)
        num_blocks = len(blocks_data) // 100
        if num_blocks == 0: return np.zeros((0, 4), dtype=np.float32)

        raw = np.frombuffer(blocks_data, dtype=np.uint8).reshape(num_blocks, 100)

        azimuths_raw = (raw[:, 2].astype(np.uint16) << 8) | raw[:, 3]
        azimuths = np.radians(azimuths_raw / 100.0)

        channels_data = raw[:, 4:100].reshape(num_blocks, 32, 3)

        dists_raw = (channels_data[:, :, 0].astype(np.uint16) << 8) | channels_data[:, :, 1]
        dists = dists_raw * 0.0025

        refls = channels_data[:, :, 2]
        valid = dists >= 0.1

        cos_a = np.cos(azimuths)[:, np.newaxis].astype(np.float32)
        sin_a = np.sin(azimuths)[:, np.newaxis].astype(np.float32)

        X = dists * self.cos_v * cos_a
        Y = dists * self.cos_v * sin_a
        Z = dists * self.sin_v

        pts = np.column_stack((X[valid], Y[valid], Z[valid], refls[valid]))
        return pts.astype(np.float32)

    def __del__(self):
        if hasattr(self, 'f'): self.f.close()