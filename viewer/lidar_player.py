import numpy as np
import datetime
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QSlider, QLabel, QLineEdit, QFileDialog, 
                               QApplication, QSpinBox, QTabWidget, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QGroupBox, QGridLayout)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIntValidator

from vispy import scene
from vispy.scene import visuals
from vispy.color import Colormap

from parser.frame_index import FrameIndex
from parser.helios_pcap_parser import HeliosParser
from cache.frame_cache import FrameCache

class LidarPlayer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.parser = None
        self.cache = None
        self.total_frames = 0
        self.current_frame = 0

        self.base_interval = 100
        self.speed_multiplier = 1.0 
        self.point_size = 2  

        self.setWindowTitle("Helios Lidar Player (Pro Telemetry)")
        self.resize(1300, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        top_layout = QHBoxLayout()
        lbl_msop = QLabel("MSOP Port:")
        top_layout.addWidget(lbl_msop)
        self.input_msop = QLineEdit("2368")
        self.input_msop.setValidator(QIntValidator(1, 65535, self))
        self.input_msop.setFixedWidth(50)
        top_layout.addWidget(self.input_msop)

        lbl_difop = QLabel("DIFOP Port:")
        top_layout.addWidget(lbl_difop)
        self.input_difop = QLineEdit("8368")
        self.input_difop.setValidator(QIntValidator(1, 65535, self))
        self.input_difop.setFixedWidth(50)
        top_layout.addWidget(self.input_difop)

        lbl_size = QLabel("Point Size:")
        top_layout.addWidget(lbl_size)
        self.spin_size = QSpinBox()
        self.spin_size.setRange(1, 20)
        self.spin_size.setValue(self.point_size)
        self.spin_size.setFixedWidth(40)
        self.spin_size.valueChanged.connect(self.change_point_size)
        top_layout.addWidget(self.spin_size)

        self.btn_load = QPushButton("Open PCAP / PCAPNG")
        self.btn_load.clicked.connect(self.load_file)
        top_layout.addWidget(self.btn_load)
        top_layout.addStretch()
        main_layout.addLayout(top_layout)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # === ВКЛАДКА 1: 3D ДВИЖОК VISPY ===
        self.tab_player = QWidget()
        player_layout = QVBoxLayout(self.tab_player)
        self.canvas = scene.SceneCanvas(keys='interactive', show=False, bgcolor='black')
        self.view = self.canvas.central_widget.add_view()
        self.view.camera = 'turntable'
        self.view.camera.distance = 50 
        self.view.camera.elevation = 30
        player_layout.addWidget(self.canvas.native)

        self.scatter = visuals.Markers(parent=self.view.scene)
        self.cmap = Colormap(['blue', 'yellow', 'red'])

        control_layout = QHBoxLayout()
        self.btn_slower = QPushButton("<<")
        self.btn_slower.setFixedWidth(40)
        self.btn_slower.clicked.connect(lambda: self.change_speed(0.5))
        control_layout.addWidget(self.btn_slower)

        self.btn_play = QPushButton("Play")
        self.btn_play.clicked.connect(self.toggle_play)
        control_layout.addWidget(self.btn_play)

        self.btn_faster = QPushButton(">>")
        self.btn_faster.setFixedWidth(40)
        self.btn_faster.clicked.connect(lambda: self.change_speed(2.0))
        control_layout.addWidget(self.btn_faster)

        self.lbl_speed = QLabel("1.0x")
        self.lbl_speed.setFixedWidth(40)
        self.lbl_speed.setAlignment(Qt.AlignCenter)
        control_layout.addWidget(self.lbl_speed)

        self.slider = QSlider(Qt.Horizontal)
        self.slider.setMinimum(0)
        self.slider.setMaximum(0)
        self.slider.setEnabled(False)
        self.slider.valueChanged.connect(self.slider_moved)
        control_layout.addWidget(self.slider)

        self.lbl_frame = QLabel("Frame: 0 / 0")
        control_layout.addWidget(self.lbl_frame)
        
        self.lbl_frame_stats = QLabel("MSOP Packets: -")
        self.lbl_frame_stats.setStyleSheet("margin-left: 20px; font-weight: bold;")
        control_layout.addWidget(self.lbl_frame_stats)
        control_layout.addStretch()
        
        player_layout.addLayout(control_layout)
        self.tabs.addTab(self.tab_player, "3D Viewer")

        # === ВКЛАДКА 2: АНАЛИТИКА DIFOP ===
        self.tab_analysis = QWidget()
        analysis_layout = QVBoxLayout(self.tab_analysis)

        self.group_static = QGroupBox("Static LiDAR Information")
        static_layout = QGridLayout(self.group_static)
        
        self.lbl_sn = QLabel("-"); self.lbl_ip = QLabel("-"); self.lbl_dest = QLabel("-"); self.lbl_mac = QLabel("-")
        self.lbl_ports = QLabel("-"); self.lbl_rpm = QLabel("-"); self.lbl_fov = QLabel("-")
        self.lbl_fw_top = QLabel("-"); self.lbl_fw_bot = QLabel("-"); self.lbl_fw_sof = QLabel("-"); self.lbl_fw_mot = QLabel("-")
        self.lbl_return_mode = QLabel("-"); self.lbl_expected = QLabel("-") # <-- НОВЫЕ ПОЛЯ

        for lbl in [self.lbl_sn, self.lbl_ip, self.lbl_dest, self.lbl_mac, self.lbl_ports, self.lbl_rpm, self.lbl_fov, 
                    self.lbl_fw_top, self.lbl_fw_bot, self.lbl_fw_sof, self.lbl_fw_mot, self.lbl_return_mode, self.lbl_expected]:
            lbl.setStyleSheet("font-weight: bold; color: #0078D7;")

        static_layout.addWidget(QLabel("Serial Number:"), 0, 0); static_layout.addWidget(self.lbl_sn, 0, 1)
        static_layout.addWidget(QLabel("LiDAR IP:"), 0, 2); static_layout.addWidget(self.lbl_ip, 0, 3)
        static_layout.addWidget(QLabel("Destination IP:"), 0, 4); static_layout.addWidget(self.lbl_dest, 0, 5)
        static_layout.addWidget(QLabel("MAC Address:"), 0, 6); static_layout.addWidget(self.lbl_mac, 0, 7)

        static_layout.addWidget(QLabel("Ports (MSOP/DIFOP):"), 1, 0); static_layout.addWidget(self.lbl_ports, 1, 1)
        static_layout.addWidget(QLabel("Target Motor Speed:"), 1, 2); static_layout.addWidget(self.lbl_rpm, 1, 3)
        static_layout.addWidget(QLabel("FOV Settings:"), 1, 4); static_layout.addWidget(self.lbl_fov, 1, 5)

        static_layout.addWidget(QLabel("Main Firmware:"), 2, 0); static_layout.addWidget(self.lbl_fw_top, 2, 1)
        static_layout.addWidget(QLabel("Bot Firmware:"), 2, 2); static_layout.addWidget(self.lbl_fw_bot, 2, 3)
        static_layout.addWidget(QLabel("APP Firmware:"), 2, 4); static_layout.addWidget(self.lbl_fw_sof, 2, 5)
        static_layout.addWidget(QLabel("Motor Firmware:"), 2, 6); static_layout.addWidget(self.lbl_fw_mot, 2, 7)

        static_layout.addWidget(QLabel("Return Mode:"), 3, 0); static_layout.addWidget(self.lbl_return_mode, 3, 1)
        static_layout.addWidget(QLabel("Expected Pkts/Frame:"), 3, 2); static_layout.addWidget(self.lbl_expected, 3, 3)

        analysis_layout.addWidget(self.group_static)

        self.table_difop = QTableWidget()
        self.table_difop.setColumnCount(10)
        self.table_difop.setHorizontalHeaderLabels([
            "Packet #", "System Time (PC)", "Hardware Time (UTC)", "Sync State", 
            "GPS Locks", "Whole Machine Voltage", "Current (A)", 
            "Bot Temp (°C)", "Main Temp (°C)", "Real RPM"
        ])
        self.table_difop.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        analysis_layout.addWidget(self.table_difop)

        self.lbl_difop_stats = QLabel("DIFOP Packets: 0 | Average Voltage: 0.00 V")
        self.lbl_difop_stats.setStyleSheet("font-size: 14px; font-weight: bold; padding: 5px;")
        analysis_layout.addWidget(self.lbl_difop_stats)

        self.tabs.addTab(self.tab_analysis, "Telemetry (DIFOP)")

        self.timer = QTimer()
        self.timer.timeout.connect(self.next_frame)
        self.is_playing = False

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "*.pcap *.pcapng")
        if not filename: return

        if self.is_playing: self.toggle_play()

        msop_port = self.input_msop.text()
        difop_port = self.input_difop.text()

        self.setWindowTitle(f"Helios Lidar Player - Loading... [{filename}]")
        QApplication.processEvents()

        index = FrameIndex(filename, msop_port=msop_port, difop_port=difop_port)
        index.load_or_build()

        self.parser = HeliosParser(filename, index, msop_port=msop_port)
        self.cache = FrameCache(max_size=50)
        self.total_frames = index.frame_count()

        self.update_telemetry(index.difop_data)

        self.setWindowTitle(f"Helios Lidar Player - {filename}")
        self.current_frame = 0
        
        if self.total_frames > 0:
            self.slider.setEnabled(True)
            self.slider.setMaximum(self.total_frames - 1)
            self.slider.setValue(0)
            self.lbl_frame.setText(f"Frame: 0 / {self.total_frames - 1}")
            self.update_frame(0)
        else:
            self.slider.setEnabled(False)
            self.scatter.set_data(pos=np.zeros((0,3))) 

    def update_telemetry(self, difop_data):
        self.table_difop.setUpdatesEnabled(False)
        self.table_difop.setRowCount(0)
        
        if not difop_data:
            self.lbl_difop_stats.setText("DIFOP Packets: 0 | No data found.")
            self.table_difop.setUpdatesEnabled(True)
            return

        first = difop_data[0]
        self.lbl_sn.setText(first.get("sn", "-"))
        self.lbl_ip.setText(first.get("lidar_ip", "-"))
        self.lbl_dest.setText(first.get("dest_ip", "-"))
        self.lbl_mac.setText(first.get("mac", "-"))
        self.lbl_ports.setText(f"{first.get('msop', '-')} / {first.get('difop', '-')}")
        
        rpm = first.get("mot_spd", 600)
        self.lbl_rpm.setText(f"{rpm} RPM")
        self.lbl_fov.setText(first.get("fov", "-"))
        self.lbl_fw_top.setText(first.get("top_frm", "-"))
        self.lbl_fw_bot.setText(first.get("bot_frm", "-"))
        self.lbl_fw_sof.setText(first.get("sof_frm", "-"))
        self.lbl_fw_mot.setText(first.get("mot_frm", "-"))
        
        ret_mode = first.get("return_mode", "Unknown")
        self.lbl_return_mode.setText(ret_mode)
        
        if rpm > 0:
            exp_pkts = int(3000 / (rpm / 60)) if ret_mode == "Dual Return" else int(1500 / (rpm / 60))
            self.lbl_expected.setText(str(exp_pkts))
        
        self.table_difop.setRowCount(len(difop_data))
        total_volt = 0.0
        count_volt = 0
        
        for row, item in enumerate(difop_data):
            self.table_difop.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            
            dt = datetime.datetime.fromtimestamp(item["ts"])
            sys_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            self.table_difop.setItem(row, 1, QTableWidgetItem(sys_time))
            self.table_difop.setItem(row, 2, QTableWidgetItem(item["hw_time"]))
            
            sync_str = f"{item['sync_mode']} | {item['sync_state']}"
            self.table_difop.setItem(row, 3, QTableWidgetItem(sync_str))
            
            gps_str = f"{item['pps_lock']} / {item['gprmc_lock']} / {item['utc_lock']}"
            gps_item = QTableWidgetItem(gps_str)
            if item['pps_lock'] == 0 or item['utc_lock'] == 0:
                gps_item.setForeground(Qt.darkYellow)
            self.table_difop.setItem(row, 4, gps_item)
            
            volt = item["voltage"]
            volt_item = QTableWidgetItem(f"{volt:.2f} V" if volt is not None else "N/A")
            if volt is not None:
                if volt < 10.0 or volt > 30.0: volt_item.setForeground(Qt.red)
                total_volt += volt
                count_volt += 1
            self.table_difop.setItem(row, 5, volt_item)
            
            curr = item["current"]
            self.table_difop.setItem(row, 6, QTableWidgetItem(f"{curr:.2f}" if curr is not None else "N/A"))
            
            t1 = item["bot_fpga_temp"]
            self.table_difop.setItem(row, 7, QTableWidgetItem(f"{t1}" if t1 is not None else "N/A"))
            
            t2 = item["main_bot_temp"]; t3 = item["main_fpga_temp"]
            s2 = f"{t2}" if t2 is not None else "N/A"
            s3 = f"{t3}" if t3 is not None else "N/A"
            self.table_difop.setItem(row, 8, QTableWidgetItem(f"{s2} / {s3}"))
            
            rpm_val = item["realtime_rpm"]
            rpm_item = QTableWidgetItem(str(rpm_val) if rpm_val is not None else "N/A")
            if rpm_val is not None and abs(rpm_val - rpm) > 20: 
                rpm_item.setForeground(Qt.red)
            self.table_difop.setItem(row, 9, rpm_item)

        avg_volt = (total_volt / count_volt) if count_volt > 0 else 0
        self.lbl_difop_stats.setText(f"DIFOP Packets: {len(difop_data)} | Average Voltage: {avg_volt:.2f} V")
        self.table_difop.setUpdatesEnabled(True)

    def change_point_size(self, value):
        self.point_size = value
        if self.total_frames > 0 and self.parser is not None:
            self.update_frame(self.current_frame)

    def change_speed(self, factor):
        self.speed_multiplier *= factor
        self.speed_multiplier = max(0.25, min(4.0, self.speed_multiplier))
        self.lbl_speed.setText(f"{self.speed_multiplier}x")
        if self.is_playing:
            new_interval = int(self.base_interval / self.speed_multiplier)
            self.timer.setInterval(new_interval)

    def toggle_play(self):
        if self.total_frames <= 0: return
        self.is_playing = not self.is_playing
        if self.is_playing:
            self.btn_play.setText("Pause")
            new_interval = int(self.base_interval / self.speed_multiplier)
            self.timer.start(new_interval)
        else:
            self.btn_play.setText("Play")
            self.timer.stop()

    def next_frame(self):
        if self.current_frame < self.total_frames - 1:
            self.slider.setValue(self.current_frame + 1)
        else:
            self.toggle_play() 

    def slider_moved(self, value):
        self.current_frame = value
        self.lbl_frame.setText(f"Frame: {value} / {self.total_frames - 1}")
        self.update_frame(value)

    def update_frame(self, frame_id):
        if not self.parser: return
        
        # --- ОБНОВЛЕННАЯ МЕТРИКА ПАКЕТОВ ---
        if hasattr(self.parser.frame_index, 'frame_stats') and frame_id < len(self.parser.frame_index.frame_stats):
            stat = self.parser.frame_index.frame_stats[frame_id]
            msop_count = stat["msop_count"]
            
            ret_mode = "Single Return"
            rpm = 600
            if self.parser.frame_index.difop_data:
                ret_mode = self.parser.frame_index.difop_data[0].get("return_mode", "Single Return")
                rpm = self.parser.frame_index.difop_data[0].get("mot_spd", 600)
            
            expected = 0
            if rpm > 0:
                expected = int(3000 / (rpm / 60)) if ret_mode == "Dual Return" else int(1500 / (rpm / 60))
                    
            loss = expected - msop_count
            color = "#FF4444" if abs(loss) > 5 else "#00FF00"
            self.lbl_frame_stats.setText(f"MSOP Packets: <span style='color:{color}'>{msop_count}</span> / {expected}")
        
        frame_data = self.cache.get(frame_id)
        if frame_data is None:
            frame_data = self.parser.load_frame(frame_id)
            self.cache.put(frame_id, frame_data)
        if frame_data is None or len(frame_data) == 0: return

        xyz = frame_data[:, :3]
        intensity = frame_data[:, 3]

        intensity_norm = np.clip(intensity / 255.0, 0.0, 1.0)
        colors = self.cmap.map(intensity_norm)

        self.scatter.set_data(pos=xyz, face_color=colors, edge_width=0, size=self.point_size)