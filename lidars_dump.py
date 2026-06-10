import asyncio
import time
import csv
import sys
import dpkt
import urllib.request
import pcap  # Библиотека для работы на Mac/Linux/Windows
import routeros_api
from urllib.error import URLError, HTTPError
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ СЕТИ И ЛИДАРОВ ---
MY_IP = "192.168.1.129"
NETWORK_INTERFACE = "en8"  # ВАЖНО: ЗАМЕНИТЕ НА ВАШ ИНТЕРФЕЙС НА MAC (например en0, en4, en5)

MSOP_PORTS = [6699, 2368]
DIFOP_PORTS = [7788, 8368]

EXPECTED_MSOP_PER_SEC = 3000  
TOLERANCE = 50
TEST_DURATION_HOURS = 8
WEB_CHECK_INTERVAL = 5.0

# --- НАСТРОЙКИ MIKROTIK ---
MIKROTIK_IP = "192.168.1.1" # IP свитча
MIKROTIK_USER = "admin"
MIKROTIK_PASS = ""

KNOWN_DEVICES = {}
devices = {}

def fetch_mac_table_from_mikrotik():
    """Стягивает таблицу портов из MikroTik"""
    print(f"[*] Подключение к MikroTik ({MIKROTIK_IP}) для получения таблицы портов...")
    try:
        connection = routeros_api.RouterOsApiPool(
            MIKROTIK_IP, username=MIKROTIK_USER, password=MIKROTIK_PASS, plaintext_login=True
        )
        api = connection.get_api()
        hosts = api.get_resource('/interface/bridge/host').get()
        
        for host in hosts:
            mac = host.get('mac-address')
            interface = host.get('on-interface')
            # Игнорируем локальные (внутренние) маки самого свитча
            if mac and interface and host.get('local') != 'true':
                KNOWN_DEVICES[mac.lower()] = interface
                
        connection.disconnect()
        print("[+] Таблица портов успешно загружена из MikroTik!")
        for m, p in KNOWN_DEVICES.items():
            print(f"    - {p} : MAC {m}")
            
    except Exception as e:
        print(f"[!] Ошибка при подключении к MikroTik: {e}")
        print("[!] Будут использоваться просто MAC-адреса вместо названий портов.")

def get_mac_string(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

def init_device(mac_str, ip_str):
    timestamp_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    # Ищем MAC в таблице свитча. Если нет - пишем просто MAC
    device_name = KNOWN_DEVICES.get(mac_str.lower(), f"Unknown_{mac_str.replace(':', '-')}")
    
    csv_filename = f"Lidar_{device_name}_Log_{timestamp_str}.csv"
    pcap_filename = f"Lidar_{device_name}_Dump_{timestamp_str}.pcap"

    csv_file = open(csv_filename, mode='w', newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_file, delimiter=';')
    csv_writer.writerow(["Время", "Имя/Порт", "MAC", "IP", "Получено MSOP", "Ожидалось MSOP", "Потеряно", "Всего потерь", "Получено DIFOP", "UDP Статус", "Web Статус"])
    
    pcap_file = open(pcap_filename, 'wb')
    pcap_writer = dpkt.pcap.Writer(pcap_file)

    devices[mac_str] = {
        "name": device_name,
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
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [+] Обнаружен лидар: {device_name} (MAC: {mac_str}, IP: {ip_str})")

def process_packet(raw_data, ts):
    try:
        eth = dpkt.ethernet.Ethernet(raw_data)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP: return
            
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_UDP: return
            
        udp = ip.data
        if udp.dport not in MSOP_PORTS and udp.dport not in DIFOP_PORTS: return
        if socket.inet_ntoa(ip.dst) != MY_IP: return
        if len(udp.data) < 1000: return

        src_mac = get_mac_string(eth.src)
        src_ip = socket.inet_ntoa(ip.src)

        if src_mac not in devices:
            init_device(src_mac, src_ip)

        device = devices[src_mac]
        device["pcap_writer"].writepkt(raw_data, ts)

        if udp.dport in MSOP_PORTS:
            device["msop_this_sec"] += 1
        elif udp.dport in DIFOP_PORTS:
            device["difop_this_sec"] += 1

    except Exception:
        pass

def capture_thread():
    """Фоновый поток для захвата пакетов через libpcap (macOS/Linux)"""
    try:
        # Открываем интерфейс в неразборчивом режиме
        sniffer = pcap.pcap(name=NETWORK_INTERFACE, promisc=True, immediate=True)
        # Фильтруем только UDP на уровне ядра, чтобы не грузить процессор
        sniffer.setfilter('udp')
        print(f"[*] Захват трафика запущен на интерфейсе: {NETWORK_INTERFACE}")
        
        # Бесконечный цикл чтения пакетов
        for ts, raw_data in sniffer:
            process_packet(raw_data, ts)
            
    except OSError as e:
        print(f"\n[!] ОШИБКА ЗАХВАТА ТРАФИКА: {e}")
        print("[!] Вы запустили скрипт с правами администратора (sudo)?")
        print(f"[!] Проверьте, существует ли интерфейс '{NETWORK_INTERFACE}' (команда ifconfig).")
        sys.exit(1)

def blocking_http_check(ip):
    url = f"http://{ip}"
    try:
        req = urllib.request.urlopen(url, timeout=2.0)
        return "OK (200)" if req.getcode() == 200 else f"Err {req.getcode()}"
    except HTTPError as e: return f"Err {e.code}"
    except URLError: return "Offline"
    except Exception: return "Error"

async def web_ui_checker(executor):
    loop = asyncio.get_running_loop()
    while True:
        checked_ips = {}
        for mac, device in devices.items():
            ip = device["ip"]
            if ip not in checked_ips:
                status = await loop.run_in_executor(executor, blocking_http_check, ip)
                checked_ips[ip] = status
            device["web_status"] = checked_ips[ip]
        await asyncio.sleep(WEB_CHECK_INTERVAL)

async def csv_logger():
    while True:
        await asyncio.sleep(1.0)
        current_time_str = datetime.now().strftime('%H:%M:%S')
        
        for mac, device in devices.items():
            msop_recv = device["msop_this_sec"]
            difop_recv = device["difop_this_sec"]
            loss_this_sec = 0

            if msop_recv == 0:
                device["udp_status"] = "Offline"
            elif msop_recv < (EXPECTED_MSOP_PER_SEC - TOLERANCE):
                loss_this_sec = EXPECTED_MSOP_PER_SEC - msop_recv
                device["total_losses_all_time"] += loss_this_sec
                device["udp_status"] = "Loss Detected"
                print(f"[!] {current_time_str} | {device['name']} | Потеряно: ~{loss_this_sec} | Web: {device['web_status']}")
            else:
                device["udp_status"] = "OK"

            device["csv_writer"].writerow([
                current_time_str, device["name"], mac, device["ip"], 
                msop_recv, EXPECTED_MSOP_PER_SEC, loss_this_sec, 
                device["total_losses_all_time"], difop_recv, 
                device["udp_status"], device["web_status"]
            ])
            device["csv_file"].flush()
            
            device["msop_this_sec"] = 0
            device["difop_this_sec"] = 0

async def main():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ЗАПУСК МОНИТОРИНГА")
    print("Нажмите Ctrl+C для завершения.\n")

    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=5)

    # Запускаем перехват пакетов в отдельном потоке (чтобы не блокировать асинхронный логгер)
    loop.run_in_executor(executor, capture_thread)

    task_csv = asyncio.create_task(csv_logger())
    task_web = asyncio.create_task(web_ui_checker(executor))

    try:
        await asyncio.sleep(TEST_DURATION_HOURS * 3600)
    except asyncio.CancelledError:
        pass
    finally:
        task_csv.cancel()
        task_web.cancel()
        executor.shutdown(wait=False)
        for mac, device in devices.items():
            device["csv_file"].close()
            device["pcap_file"].close()
        print("\n[+] Мониторинг остановлен. Файлы сохранены.")

import socket
if __name__ == "__main__":
    # Сначала пытаемся получить таблицу из MikroTik
    fetch_mac_table_from_mikrotik()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass