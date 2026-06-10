#!/usr/bin/env python3
"""
Визуализатор облака точек RoboSense Helios 32 из PCAP-файла (MSOP).
Фильтрует пакеты по портам MSOP/DIFOP и (опционально) по IP-адресу отправителя.
Пример для вашей конфигурации:
    python visual.py lidars-dump.pcap --model 70 --rpm 600 --sender-ip 192.168.1.201
"""

import argparse
import struct
import numpy as np
import sys

from scapy.all import rdpcap, UDP, IP

# Пытаемся импортировать Open3D
try:
    import open3d as o3d
    OPEN3D_AVAILABLE = True
except ImportError:
    OPEN3D_AVAILABLE = False
    print("Open3D не найден. Будет выведена только статистика.\n"
          "Установите: pip install open3d", file=sys.stderr)

# ---------------------------------------------------------------------
# Вертикальные углы для разных моделей Helios 32
# ---------------------------------------------------------------------
VERTICAL_ANGLES = {
    70: [
        15.0, 13.0, 11.0, 9.0, 7.0, 5.5, 4.0, 2.67, 1.33, 0.0,
        -1.33, -2.67, -4.0, -5.33, -6.67, -8.0, -10.0, -16.0,
        -13.0, -19.0, -22.0, -28.0, -25.0, -31.0, -34.0, -37.0,
        -40.0, -43.0, -46.0, -49.0, -52.0, -55.0
    ],
    31: [
        15.0, 14.0, 13.0, 12.0, 11.0, 10.0, 9.0, 8.0, 7.0, 6.0,
        5.0, 4.0, 3.0, 2.0, 1.0, 0.0, -1.0, -2.0, -3.0, -4.0,
        -5.0, -6.0, -7.0, -8.0, -9.0, -10.0, -11.0, -12.0,
        -13.0, -14.0, -15.0, -16.0
    ],
    26: [
        10.0, 9.0, 7.5, 5.5, 3.5, 2.5, 1.5, 0.5, -0.5, -1.5,
        -2.5, -3.5, -4.5, -5.5, -6.5, -7.5, -8.5, -9.5, -10.5,
        -11.5, -12.5, -13.5, -14.5, -15.5, -16.5, -17.5, -18.5,
        -19.5, -20.5, -21.5, -22.5, -23.5
    ]
}

# Смещения времени (Single Return) из таблицы 32 документации
TIME_OFFSETS_US = [
    0.00, 1.74, 3.47, 5.21, 6.94, 8.68, 10.42, 12.15,
    13.89, 15.62, 17.36, 19.10, 20.83, 22.57, 24.30, 26.04,
    27.78, 29.51, 31.25, 32.98, 34.72, 36.46, 38.19, 39.93,
    41.66, 43.40, 45.14, 46.87, 48.61, 50.34, 52.08, 53.82
]

# ---------------------------------------------------------------------
class HeliosMSOPParser:
    def __init__(self, model_fov=70, rpm=600):
        if model_fov not in VERTICAL_ANGLES:
            raise ValueError(f"Неизвестная модель: {model_fov}. Доступны: {list(VERTICAL_ANGLES.keys())}")
        self.vertical_angles_rad = np.deg2rad(VERTICAL_ANGLES[model_fov], dtype=np.float64)
        self.rpm = rpm
        self.angular_speed = rpm * 2 * np.pi / 60.0   # рад/с
        self.azimuth_scale = 0.01 * np.pi / 180.0     # 0.01° -> радианы
        self.distance_scale = 0.0025                   # 0.25 см -> метры
        self.block_flag = 0xFFEE
        self.time_offsets_us = np.array(TIME_OFFSETS_US, dtype=np.float64)

    def parse_packet(self, data: bytes):
        if len(data) < 42 + 1200 + 6:
            return None
        # Проверка синхрозаголовка (little-endian 0x55_aa_05_5a)
        if struct.unpack_from('<I', data, 0)[0] != 0x5a05aa55:
            return None

        points = []
        base_offset = 42
        for block_idx in range(12):
            offset = base_offset + block_idx * 100
            flag = struct.unpack_from('<H', data, offset)[0]
            if flag != self.block_flag:
                continue

            azimuth_raw = struct.unpack_from('<H', data, offset + 2)[0]
            azimuth = azimuth_raw * self.azimuth_scale

            for ch in range(32):
                ch_offset = offset + 4 + ch * 3
                dist_raw = struct.unpack_from('<H', data, ch_offset)[0]
                reflectivity = data[ch_offset + 2]
                if dist_raw == 0:
                    continue
                distance = dist_raw * self.distance_scale

                delta_angle = self.angular_speed * self.time_offsets_us[ch] * 1e-6
                alpha = azimuth + delta_angle
                omega = self.vertical_angles_rad[ch]

                cos_omega = np.cos(omega)
                x = distance * cos_omega * np.sin(alpha)
                y = distance * cos_omega * np.cos(alpha)
                z = distance * np.sin(omega)

                points.append([x, y, z, reflectivity])

        if not points:
            return None
        return np.array(points, dtype=np.float32)

# ---------------------------------------------------------------------
def load_pcap(filename, parser, msop_port=2368, difop_port=8368, sender_ip=None):
    """
    Читает pcap-файл, фильтрует UDP-пакеты на MSOP-порт,
    парсит и возвращает массив точек (N x 4).
    Если задан sender_ip, дополнительно фильтрует по IP-адресу отправителя.
    """
    print(f"Чтение {filename} (MSOP порт {msop_port}, DIFOP порт {difop_port})...")
    if sender_ip:
        print(f"Фильтр по IP-адресу отправителя: {sender_ip}")
    packets = rdpcap(filename)

    all_points = []
    msop_count = 0
    difop_count = 0

    for pkt in packets:
        # Безопасная проверка наличия IP и UDP слоёв
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            continue
        ip = pkt[IP]
        udp = pkt[UDP]

        # Фильтр по IP-адресу отправителя (если указан)
        if sender_ip and ip.src != sender_ip:
            continue

        # Проверяем порт назначения (обычно это dport, когда компьютер принимает)
        if udp.sport == msop_port or udp.dport == msop_port:
            try:
                payload = bytes(udp.payload)
                pts = parser.parse_packet(payload)
                if pts is not None:
                    all_points.append(pts)
                    msop_count += 1
            except Exception:
                continue
        elif udp.sport == difop_port or udp.dport == difop_port:
            difop_count += 1   # просто подсчитываем, парсить не будем

    print(f"Найдено MSOP-пакетов: {msop_count}, DIFOP-пакетов: {difop_count}")
    if not all_points:
        print("Не найдено ни одного корректного MSOP-пакета.")
        return None
    points = np.concatenate(all_points, axis=0)
    print(f"Всего точек: {len(points)}")
    return points

# ---------------------------------------------------------------------
def visualize_points(points):
    if not OPEN3D_AVAILABLE:
        print(f"Средняя отражательная способность: {np.mean(points[:,3]):.2f}")
        return

    pcd = o3d.geometry.PointCloud()
    pcd.points = o3d.utility.Vector3dVector(points[:, :3])
    # Цвет по интенсивности (0..255)
    intens = np.clip(points[:, 3] / 255.0, 0, 1)
    colors = np.repeat(intens.reshape(-1, 1), 3, axis=1) * 0.8 + 0.2
    pcd.colors = o3d.utility.Vector3dVector(colors)
    o3d.visualization.draw_geometries([pcd], window_name="Helios 32 PCAP")

# ---------------------------------------------------------------------
if __name__ == '__main__':
    parser_arg = argparse.ArgumentParser(description="Визуализатор MSOP из PCAP для Helios 32")
    parser_arg.add_argument('pcap_file', help='Путь к .pcap файлу')
    parser_arg.add_argument('--model', type=int, choices=[70, 31, 26], default=70,
                            help='Модель лидара (70, 31, 26)')
    parser_arg.add_argument('--rpm', type=int, default=600, help='Скорость вращения, об/мин')
    parser_arg.add_argument('--msop-port', type=int, default=2368, help='UDP порт MSOP')
    parser_arg.add_argument('--difop-port', type=int, default=8368, help='UDP порт DIFOP')
    parser_arg.add_argument('--sender-ip', type=str, default=None,
                            help='IP-адрес отправителя (лидара) для дополнительной фильтрации')
    args = parser_arg.parse_args()

    # Создаём парсер
    msop_parser = HeliosMSOPParser(model_fov=args.model, rpm=args.rpm)

    # Загружаем данные с фильтрацией по IP отправителя
    points = load_pcap(args.pcap_file, msop_parser, args.msop_port, args.difop_port,
                       sender_ip=args.sender_ip)

    if points is not None:
        visualize_points(points)
    else:
        print("Нет данных для отображения.")