#!/usr/bin/env python3
"""
Диагностика потерь пакетов лидара Helios 32.
Сравнивает счётчик MSOP (пользовательское поле в UDP payload) и IP identification.
"""

from scapy.all import rdpcap, IP, UDP
import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(description="Анализ pcap для проверки потерь лидара")
    parser.add_argument("pcap_file", help="Путь к pcap-файлу")
    parser.add_argument("--src_ip", default="192.168.1.201", help="IP-адрес лидара")
    parser.add_argument("--port", type=int, default=6699, help="Порт MSOP (по умолчанию 6699)")
    parser.add_argument("--msop_offset", type=int, default=8, help="Смещение счётчика MSOP от начала UDP payload (байт)")
    parser.add_argument("--msop_size", type=int, choices=[1,2,4], default=4, help="Размер счётчика MSOP (1,2 или 4 байта)")
    parser.add_argument("--msop_endian", choices=["big", "little"], default="big", help="Порядок байт счётчика MSOP")
    return parser.parse_args()

def bytes_to_int(data, size, endian):
    if endian == "big":
        return int.from_bytes(data[:size], byteorder='big')
    else:
        return int.from_bytes(data[:size], byteorder='little')

def main():
    args = parse_args()
    print(f"Чтение файла: {args.pcap_file}")
    try:
        packets = rdpcap(args.pcap_file)
    except Exception as e:
        print(f"Ошибка чтения pcap: {e}")
        sys.exit(1)

    # Таблица для отобранных пакетов
    records = []   # каждый элемент: (ip_id, msop_counter)

    for pkt in packets:
        # Проверяем, что пакет содержит IP и UDP
        if IP not in pkt or UDP not in pkt:
            continue
        ip_layer = pkt[IP]
        udp_layer = pkt[UDP]

        # Фильтр по источнику и порту назначения
        if ip_layer.src != args.src_ip or udp_layer.dport != args.port:
            continue

        ip_id = ip_layer.id   # int
        payload = bytes(udp_layer.payload)
        if len(payload) < args.msop_offset + args.msop_size:
            # Не хватает данных – пропускаем
            continue

        msop_raw = payload[args.msop_offset:args.msop_offset+args.msop_size]
        try:
            msop_val = bytes_to_int(msop_raw, args.msop_size, args.msop_endian)
        except:
            continue

        records.append((ip_id, msop_val))

    if len(records) < 2:
        print("Найдено менее 2 пакетов. Проверьте фильтры (IP, порт) и правильность смещения счётчика.")
        sys.exit(0)

    print(f"Всего отобрано пакетов: {len(records)}")
    print("Анализ последовательных разностей:")
    print("{:<8} {:<12} {:<12} {:<12} {:<12}".format("№ пакета", "IP ID", "MSOP", "Δ IP ID", "Δ MSOP"))
    print("-" * 60)

    mismatches = 0
    for i in range(1, len(records)):
        prev_ip, prev_msop = records[i-1]
        curr_ip, curr_msop = records[i]
        delta_ip = curr_ip - prev_ip
        delta_msop = curr_msop - prev_msop

        print("{:<8} {:<12} {:<12} {:<12} {:<12}".format(i, prev_ip, prev_msop, "", ""))
        print("{:<8} {:<12} {:<12} {:<12} {:<12}".format(i+1, curr_ip, curr_msop, delta_ip, delta_msop))
        print()

        if delta_ip != delta_msop:
            mismatches += 1
            print(f"  ! НЕСОВПАДЕНИЕ: ΔIP={delta_ip}, ΔMSOP={delta_msop}")
        else:
            if delta_ip != 1:
                print(f"  Одинаковая потеря: ΔIP = ΔMSOP = {delta_ip} (потеряно {delta_ip-1} пакетов)")
            else:
                print("  Норма (оба счётчика увеличились на 1)")

    print("\n--- РЕЗЮМЕ ---")
    if mismatches == 0:
        print("✅ Все разности совпадают. Это означает, что если были потери, то они происходили ПОСЛЕ формирования пакета лидаром (т.е. в сети или на приёмной стороне).")
    else:
        print(f"❌ Найдено {mismatches} несовпадений разностей. Это указывает на возможные проблемы ВНУТРИ лидара (или неверно задано смещение счётчика MSOP).")

if __name__ == "__main__":
    main()