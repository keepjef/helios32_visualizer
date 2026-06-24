import asyncio
import socket
import time
import csv
import sys
import os
import dpkt
import threading
import queue
import struct
import ctypes
from urllib.error import URLError, HTTPError
from urllib.request import urlopen
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import conf
except ImportError:
    print("\n[!!!] КРИТИЧЕСКАЯ ОШИБКА: Библиотека scapy не установлена!")
    print("[!!!] Поскольку у Лидаров одинаковые IP, нам нужен прямой доступ к драйверу.")
    print("[!!!] Выполните в консоли команду: pip install scapy")
    sys.exit(1)

# --- НАСТРОЙКИ ---
MSOP_PORTS = [6699, 2368]
DIFOP_PORTS = [7788, 8368]
EXPECTED_MSOP_PER_SEC = 3000
TOLERANCE = 150
TEST_DURATION_HOURS = 8
WEB_CHECK_INTERVAL = 5.0

# --- ГЛОБАЛЬНЫЕ ОБЪЕКТЫ ---
# Главным ключом теперь выступает уникальный MAC-АДРЕС, считанный напрямую с кабеля!
devices = {} 
target_to_local_ip = {}
packet_queue = queue.Queue(maxsize=2000000)
data_lock = threading.Lock()
is_running = True

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def get_dst_ip_for_pcap(src_ip):
    if src_ip not in target_to_local_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((src_ip, 1))
            target_to_local_ip[src_ip] = s.getsockname()[0]
            s.close()
        except Exception:
            target_to_local_ip[src_ip] = "255.255.255.255"
    return target_to_local_ip[src_ip]

def init_device(mac_str, ip_str):
    safe_mac = mac_str.replace(":", "-").upper()
    safe_ip = ip_str.replace(".", "-")
    
    # Файлы теперь четко называются по MAC-адресу
    csv_filename = f"Lidar_MAC_{safe_mac}_IP_{safe_ip}.csv"
    pcap_filename = f"Lidar_MAC_{safe_mac}_IP_{safe_ip}.pcap"
    
    csv_file = open(csv_filename, mode='w', newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_file, delimiter=';')
    csv_writer.writerow(["Время", "MAC Лидара", "IP Источника", "Получено MSOP", "Ожидалось MSOP", "Потеряно за сек", "Всего потерь", "Получено DIFOP", "UDP Статус", "Web Статус"])
    
    pcap_file = open(pcap_filename, 'wb', buffering=16777216)
    pcap_writer = dpkt.pcap.Writer(pcap_file)
    
    devices[mac_str] = {
        "mac": mac_str,
        "ip": ip_str,
        "msop_this_sec": 0, 
        "difop_this_sec": 0, 
        "total_losses_all_time": 0, 
        "udp_status": "Online", 
        "web_status": "Waiting...", 
        "csv_file": csv_file, 
        "csv_writer": csv_writer, 
        "pcap_file": pcap_file, 
        "pcap_writer": pcap_writer
    }
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [+] ОБНАРУЖЕН НОВЫЙ ЛИДАР! MAC: {mac_str} | Созданы файлы: {csv_filename}, {pcap_filename}")

def create_fast_pcap_packet(src_ip, dst_ip, sport, dport, payload, mac_str):
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    src_mac_bytes = bytes.fromhex(mac_str.replace('-', ''))
    dst_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
    
    udp_len = 8 + len(payload)
    udp_header = struct.pack('!HHHH', sport, dport, udp_len, 0)
    
    ip_len = 20 + udp_len
    ip_header = struct.pack('!BBHHHBBH', 0x45, 0, ip_len, 0, 0, 64, 17, 0) + src_ip_bytes + dst_ip_bytes
    eth_header = dst_mac_bytes + src_mac_bytes + struct.pack('!H', 0x0800)
    
    return eth_header + ip_header + udp_header + payload

# --- ПОТОК №1: ЗАХВАТ L2-УРОВНЯ ЧЕРЕЗ NPCAP (WIRESHARK ENGINE) ---
def scapy_l2_capture_worker():
    print(f"[i] Подключение к сетевому драйверу Npcap/WinPcap для извлечения MAC-адресов...")
    
    # Пытаемся найти правильный сетевой интерфейс, который смотрит в локальную сеть
    target_iface = conf.iface
    for iface_name, iface in conf.ifaces.items():
        if hasattr(iface, 'ip') and iface.ip and iface.ip.startswith("192."):
            target_iface = iface
            break
            
    try:
        # Устанавливаем хардварный BPF-фильтр в драйвер, чтобы отсечь мусор и повысить FPS до небес
        bpf_filter = "udp and (" + " or ".join(f"port {p}" for p in MSOP_PORTS + DIFOP_PORTS) + ")"
        sock = conf.L2listen(iface=target_iface, filter=bpf_filter)
        print(f"[i] Успешный перехват L2-трафика на интерфейсе: {target_iface.name}")
    except OSError as e:
        print(f"\n[!!!] КРИТИЧЕСКАЯ ОШИБКА ДРАЙВЕРА: {e}")
        print("[!!!] Убедитесь, что скрипт запущен от имени Администратора!")
        os._exit(1)

    target_ports = set(MSOP_PORTS + DIFOP_PORTS)
    put = packet_queue.put
    t_time = time.time
    
    # Попытка получить прямой доступ к памяти драйвера для экстремальной скорости (до 10 млн пакетов/сек)
    pcap = getattr(sock, 'ins', None)
    use_raw = hasattr(pcap, 'next')
    
    if use_raw:
        print("[i] Активирован режим ULTRA-FAST (прямое чтение памяти драйвера)")
        while is_running:
            try:
                hdr, pkt_bytes = pcap.next()
                if not pkt_bytes: continue
                
                # Парсинг сырого Ethernet (14 байт)
                # Вытаскиваем ИСТИННЫЙ MAC-АДРЕС источника (байты 6-11)
                mac_bytes = pkt_bytes[6:12]
                src_mac = f"{mac_bytes[0]:02X}-{mac_bytes[1]:02X}-{mac_bytes[2]:02X}-{mac_bytes[3]:02X}-{mac_bytes[4]:02X}-{mac_bytes[5]:02X}"
                
                # Длина IP заголовка
                ihl = (pkt_bytes[14] & 0xF) * 4
                udp_offset = 14 + ihl
                
                # Парсинг портов
                sport, dport, ulen, _ = struct.unpack('!HHHH', pkt_bytes[udp_offset:udp_offset+8])
                
                payload = pkt_bytes[udp_offset+8:udp_offset+ulen]
                
                # Парсинг IP (байты 26-29 заголовка IP)
                src_ip = f"{pkt_bytes[14+12]}.{pkt_bytes[14+13]}.{pkt_bytes[14+14]}.{pkt_bytes[14+15]}"
                
                put((payload, src_ip, sport, dport, t_time(), src_mac))
            except Exception: pass
    else:
        print("[i] Включен стандартный режим захвата Scapy")
        while is_running:
            try:
                pkt = sock.recv()
                if pkt.haslayer("UDP"):
                    dport = pkt["UDP"].dport
                    if dport in target_ports:
                        src_mac = pkt["Ether"].src.replace(":", "-").upper()
                        payload = bytes(pkt["UDP"].payload)
                        src_ip = pkt["IP"].src
                        put((payload, src_ip, pkt["UDP"].sport, dport, t_time(), src_mac))
            except Exception: pass

# --- ПОТОК №2: ОБРАБОТЧИК ПАКЕТОВ ---
def packet_processor_thread():
    get_pkt = packet_queue.get 
    
    while is_running or not packet_queue.empty():
        try:
            payload, src_ip, sport, dport, ts, src_mac = get_pkt(timeout=1.0)
            if len(payload) < 1000: continue
            
            # Если видим этот уникальный MAC-адрес впервые — инициализируем для него файлы!
            if src_mac not in devices:
                with data_lock:
                    if src_mac not in devices:
                        init_device(src_mac, src_ip)
            
            device = devices[src_mac]
            dst_ip_str = get_dst_ip_for_pcap(src_ip)
            
            # Записываем пакет в индивидуальный pcap лидара
            raw_pcap_bytes = create_fast_pcap_packet(src_ip, dst_ip_str, sport, dport, payload, src_mac)
            device["pcap_writer"].writepkt(raw_pcap_bytes, ts)
            
            with data_lock:
                if dport in MSOP_PORTS: device["msop_this_sec"] += 1
                else: device["difop_this_sec"] += 1
                
        except queue.Empty: continue
        except Exception as e:
            if is_running: print(f"[!] Ошибка в обработчике: {e}")

# --- ПОТОК №3: ПРОВЕРКА WEB-ИНТЕРФЕЙСА ---
# Примечание: так как у всех лидаров одинаковый IP (192.168.1.201),
# HTTP-запрос достучится только до одного случайного лидара. Это ограничение TCP/IP Windows.
def blocking_http_check(ip):
    try:
        req = urlopen(f"http://{ip}", timeout=1.5)
        return f"OK ({req.getcode()})"
    except HTTPError as e: return f"Err {e.code}"
    except Exception: return "Offline"

async def web_ui_checker(executor):
    loop = asyncio.get_running_loop()
    while is_running:
        items = list(devices.values())
        tasks = [loop.run_in_executor(executor, blocking_http_check, device['ip']) for device in items]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            with data_lock:
                for device, status in zip(items, results):
                    device["web_status"] = status if not isinstance(status, Exception) else "Error"
        await asyncio.sleep(WEB_CHECK_INTERVAL)

# --- ПОТОК №4: ЛОГГЕР CSV ---
async def csv_logger():
    while is_running:
        await asyncio.sleep(1.0)
        current_time_str = datetime.now().strftime('%H:%M:%S')
        
        snapshot = []
        with data_lock:
            for mac_addr, device in devices.items():
                msop = device["msop_this_sec"]
                difop = device["difop_this_sec"]
                device["msop_this_sec"] = 0
                device["difop_this_sec"] = 0
                snapshot.append((mac_addr, device, msop, difop))
        
        for mac_addr, device, msop_recv, difop_recv in snapshot:
            loss_this_sec = 0
            if 0 < msop_recv < (EXPECTED_MSOP_PER_SEC - TOLERANCE):
                loss_this_sec = EXPECTED_MSOP_PER_SEC - msop_recv
                device["total_losses_all_time"] += loss_this_sec
                device["udp_status"] = "Loss"
                print(f"[!] {current_time_str} | MAC: {mac_addr} | Потеряно: ~{loss_this_sec}")
            elif msop_recv == 0: 
                device["udp_status"] = "Offline"
            else: 
                device["udp_status"] = "OK"
            
            device["csv_writer"].writerow([current_time_str, mac_addr, device["ip"], msop_recv, EXPECTED_MSOP_PER_SEC, loss_this_sec, device["total_losses_all_time"], difop_recv, device["udp_status"], device["web_status"]])
            device["csv_file"].flush()

async def main():
    global is_running
    if not is_admin():
        print("\n[!!!] ОШИБКА: Запустите консоль или IDE (PyCharm) от имени Администратора!")
        print("[!!!] Для доступа к MAC-адресам требуются повышенные привилегии.")
        sys.exit(1)
        
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ЗАПУСК В РЕЖИМЕ ЖЕСТКОГО MAC-РАЗДЕЛЕНИЯ (NPCAP)")
    
    capture_thread = threading.Thread(target=scapy_l2_capture_worker, daemon=True)
    processor_thread = threading.Thread(target=packet_processor_thread, daemon=True)
    
    capture_thread.start()
    processor_thread.start()
    
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=20)
    
    tasks = [
        asyncio.create_task(csv_logger()),
        asyncio.create_task(web_ui_checker(executor))
    ]
    
    try: await asyncio.sleep(TEST_DURATION_HOURS * 3600)
    except asyncio.CancelledError: pass
    finally:
        is_running = False
        print("\n[i] Сохранение файлов...")
        
        capture_thread.join(timeout=1.0)
        processor_thread.join(timeout=5.0)
        
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        executor.shutdown(wait=True)
        
        for device in devices.values():
            device["csv_file"].close()
            device["pcap_file"].flush()
            device["pcap_file"].close()
            
        print("[+] Все файлы закрыты.")

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass