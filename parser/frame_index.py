import os
import json
import datetime
import numpy as np
import dpkt

class FrameIndex:
    def __init__(self, pcap_path, msop_port=2368, difop_port=8368):
        self.pcap_path = pcap_path
        self.msop_port = int(msop_port)
        self.difop_port = int(difop_port)
        
        self.index_path = pcap_path + f'_msop{self.msop_port}.index.npy'
        self.difop_path = pcap_path + f'_difop{self.difop_port}.json'
        
        self.frame_packets = []
        self.frame_stats = []
        self.difop_data = []

    def load_or_build(self):
        if os.path.exists(self.index_path) and os.path.exists(self.difop_path):
            print(f"Загрузка кэша из {self.index_path} и {self.difop_path}...")
            self.frame_packets = np.load(self.index_path).tolist()
            try:
                with open(self.difop_path, 'r') as f:
                    data = json.load(f)
                    self.difop_data = data.get("difop", [])
                    self.frame_stats = data.get("stats", [])
                return
            except Exception as e:
                print(f"Ошибка чтения кэша: {e}. Перестраиваем...")

        self.build_index()
        np.save(self.index_path, np.array(self.frame_packets))
        with open(self.difop_path, 'w') as f:
            json.dump({"difop": self.difop_data, "stats": self.frame_stats}, f)

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
                return udp.dport, udp.data
            except: pass
        return None, None

    def build_index(self):
        print(f"Построение индекса (MSOP: {self.msop_port}, DIFOP: {self.difop_port})...")
        self.frame_packets = [0]
        self.frame_stats = []
        last_azimuth = -1
        
        valid_msop_count = 0
        valid_difop_count = 0
        current_msop_count = 0
        
        with open(self.pcap_path, 'rb', buffering=16 * 1024 * 1024) as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)

            packet_idx = 0
            for ts, buf in reader:
                dport, payload = self._get_udp_payload(buf)
                
                # --- MSOP ---
                if dport == self.msop_port and payload and len(payload) >= 142:
                    valid_msop_count += 1
                    current_msop_count += 1
                    
                    azimuth = ((payload[44] << 8) | payload[45]) / 100.0
                    if last_azimuth != -1 and abs(azimuth - last_azimuth) > 90:
                        self.frame_packets.append(packet_idx)
                        self.frame_stats.append({
                            "msop_count": current_msop_count
                        })
                        current_msop_count = 0
                    last_azimuth = azimuth
                    
                # --- DIFOP ---
                elif dport == self.difop_port and payload and len(payload) >= 1200:
                    if payload[0] == 0xA5 and payload[1] == 0xFF:
                        valid_difop_count += 1
                        try:
                            # 1. Статика
                            mot_spd = int.from_bytes(payload[8:10], 'big')
                            lidar_ip = f"{payload[10]}.{payload[11]}.{payload[12]}.{payload[13]}"
                            dest_ip = f"{payload[14]}.{payload[15]}.{payload[16]}.{payload[17]}"
                            mac = f"{payload[18]:02X}:{payload[19]:02X}:{payload[20]:02X}:{payload[21]:02X}:{payload[22]:02X}:{payload[23]:02X}"
                            msop_port_val = int.from_bytes(payload[24:26], 'big')
                            difop_port_val = int.from_bytes(payload[28:30], 'big')
                            fov_start = int.from_bytes(payload[32:34], 'big') / 100.0
                            fov_end = int.from_bytes(payload[34:36], 'big') / 100.0
                            top_frm = " ".join([f"{x:02X}" for x in payload[38:43]])
                            bot_frm = " ".join([f"{x:02X}" for x in payload[43:48]])
                            sof_frm = " ".join([f"{x:02X}" for x in payload[48:53]])
                            mot_frm = " ".join([f"{x:02X}" for x in payload[53:58]])
                            sn = "".join([f"{x:02X}" for x in payload[58:64]])
                            
                            # === НОВОЕ: Определение режима возврата из смещения 300 ===
                            ret_mode_val = payload[300]
                            return_mode = {
                                0x00: "Dual Return",
                                0x04: "Strongest Return",
                                0x05: "Last Return",
                                0x06: "First Return"
                            }.get(ret_mode_val, f"Unknown (0x{ret_mode_val:02X})")
                            
                            # 2. Синхронизация и время
                            sync_mode_val = payload[301]
                            sync_mode = {0: "GPS", 1: "E2E-L4", 2: "P2P", 3: "gPTP", 4: "E2E-L2"}.get(sync_mode_val, str(sync_mode_val))
                            sync_state_val = payload[302]
                            sync_state = {0: "Not Sync", 1: "GPS Sync", 2: "PTP Sync"}.get(sync_state_val, str(sync_state_val))
                            
                            hw_sec = int.from_bytes(payload[303:309], 'big')
                            hw_us = int.from_bytes(payload[309:313], 'big')
                            try:
                                hw_dt = datetime.datetime.fromtimestamp(hw_sec, tz=datetime.timezone.utc)
                                hw_time_str = f"{hw_dt.strftime('%Y-%m-%d %H:%M:%S')}.{hw_us:06d} UTC"
                            except Exception:
                                hw_time_str = f"Raw: {hw_sec}s {hw_us}us"
                            
                            # 3. Динамические статусы
                            current_raw = int.from_bytes(payload[313:315], 'big')
                            current = round(current_raw / 4096.0 * 5.0, 2) if current_raw != 0xFFFF else None
                            
                            voltage_raw = int.from_bytes(payload[317:319], 'big')
                            voltage = round(voltage_raw / 4096.0 * 24.5, 2) if voltage_raw != 0xFFFF else None
                            
                            bot_fpga_raw = int.from_bytes(payload[331:333], 'big')
                            bot_fpga_temp = round(503.975 * bot_fpga_raw / 4096.0 - 273.15, 1) if bot_fpga_raw != 0xFFFF else None
                            
                            main_bot_raw = int.from_bytes(payload[337:339], 'big')
                            main_bot_temp = round(200.0 * main_bot_raw / 4096.0 - 50.0, 1) if main_bot_raw != 0xFFFF else None
                            
                            main_fpga_raw = int.from_bytes(payload[339:341], 'big')
                            main_fpga_temp = round(503.975 * main_fpga_raw / 4096.0 - 273.15, 1) if main_fpga_raw != 0xFFFF else None
                            
                            rpm_raw = int.from_bytes(payload[341:343], 'big')
                            realtime_rpm = rpm_raw if rpm_raw < 0xF000 else None
                            
                            gps_st = payload[348]
                            pps_lock = (gps_st & 1)
                            gprmc_lock = (gps_st >> 1) & 1
                            utc_lock = (gps_st >> 2) & 1

                            self.difop_data.append({
                                "ts": ts, "mot_spd": mot_spd, "lidar_ip": lidar_ip, "dest_ip": dest_ip,
                                "mac": mac, "msop": msop_port_val, "difop": difop_port_val,
                                "fov": f"{fov_start}° - {fov_end}°", "sn": sn, "top_frm": top_frm,
                                "bot_frm": bot_frm, "sof_frm": sof_frm, "mot_frm": mot_frm,
                                "return_mode": return_mode, "sync_mode": sync_mode, 
                                "sync_state": sync_state, "hw_time": hw_time_str,
                                "current": current, "voltage": voltage, "bot_fpga_temp": bot_fpga_temp,
                                "main_bot_temp": main_bot_temp, "main_fpga_temp": main_fpga_temp,
                                "realtime_rpm": realtime_rpm, "pps_lock": pps_lock,
                                "gprmc_lock": gprmc_lock, "utc_lock": utc_lock
                            })
                        except Exception:
                            pass

                packet_idx += 1
                
        self.frame_stats.append({
            "msop_count": current_msop_count
        })
        
        print(f"Прочитано MSOP (3D): {valid_msop_count}")
        print(f"Прочитано DIFOP (Телеметрия): {valid_difop_count}")

    def frame_count(self):
        return len(self.frame_packets)