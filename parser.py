# parser/helios_pcap_parser.py

import struct
import numpy as np
from scapy.all import PcapReader, UDP


VERTICAL_ANGLES = np.radians([
    15, 13, 11, 9, 7, 5.5, 4, 2.67,
    1.33, 0, -1.33, -2.67, -4, -5.33,
    -6.67, -8, -10, -16, -13, -19,
    -22, -28, -25, -31, -34, -37,
    -40, -43, -46, -49, -52, -55
])

MSOP_PORT = 2368


class HeliosFrameParser:

    def __init__(self):
        self.current_frame = []

    def parse_pcap(self, pcap_file):

        previous_azimuth = None

        with PcapReader(pcap_file) as reader:

            for pkt in reader:

                if UDP not in pkt:
                    continue

                if pkt[UDP].dport != MSOP_PORT:
                    continue

                payload = bytes(pkt[UDP].payload)

                if len(payload) != 1248:
                    continue

                points, frame_complete, previous_azimuth = \
                    self.parse_msop_packet(
                        payload,
                        previous_azimuth
                    )

                self.current_frame.extend(points)

                if frame_complete:

                    frame = np.asarray(
                        self.current_frame,
                        dtype=np.float32
                    )

                    self.current_frame = []

                    yield frame

    def parse_msop_packet(
        self,
        data,
        previous_azimuth
    ):

        frame_complete = False
        points = []

        offset = 42

        for block_idx in range(12):

            block = data[offset:offset + 100]

            flag = block[0:2]

            if flag != b'\xff\xee':
                offset += 100
                continue

            azimuth_raw = struct.unpack(
                ">H",
                block[2:4]
            )[0]

            azimuth = np.radians(
                azimuth_raw / 100.0
            )

            if previous_azimuth is not None:

                if azimuth < previous_azimuth:
                    frame_complete = True

            previous_azimuth = azimuth

            channel_offset = 4

            for channel in range(32):

                start = channel_offset + channel * 3

                distance_raw = struct.unpack(
                    ">H",
                    block[start:start + 2]
                )[0]

                reflectivity = block[start + 2]

                distance = distance_raw * 0.0025

                if distance < 0.1:
                    continue

                vertical = VERTICAL_ANGLES[channel]

                x = distance * np.cos(vertical) * np.cos(azimuth)

                y = distance * np.cos(vertical) * np.sin(azimuth)

                z = distance * np.sin(vertical)

                points.append(
                    [
                        x,
                        y,
                        z,
                        reflectivity
                    ]
                )

            offset += 100

        return points, frame_complete, previous_azimuth