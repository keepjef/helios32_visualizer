import numpy as np
import datetime
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QSlider, QLabel, QLineEdit, QFileDialog, 
                               QApplication, QSpinBox, QTabWidget, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QGroupBox, QGridLayout,
                               QCheckBox, QDoubleSpinBox)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIntValidator

from vispy import scene
from vispy.scene import visuals
from vispy.color import Colormap
from vispy.visuals.transforms import STTransform

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

        # --- НОВЫЕ КООРДИНАТЫ ЗОНЫ ДЕТЕКЦИИ ПО УМОЛЧАНИЮ ---
        self.roi_min = np.array([-0.61560, -0.27765, -0.00780])
        self.roi_max = np.array([0.25920, 0.27765, 0.47000])
        
        # --- Смещения по осям (остаются по нулям при старте) ---
        self.offset_x = 0.0
        self.offset_y = 0.0
        self.offset_z = 0.0

        self.setWindowTitle("Helios Lidar Player (Pro Telemetry + ROI Tuner)")
        self.resize(1350, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- ВЕРХНЯЯ ПАНЕЛЬ ---
        top_layout = QHBoxLayout()
        
        self.input_msop = QLineEdit("2368")
        self.input_msop.setValidator(QIntValidator(1, 65535, self))
        self.input_msop.setFixedWidth(40)
        top_layout.addWidget(QLabel("MSOP:"))
        top_layout.addWidget(self.input_msop)

        self.input_difop = QLineEdit("8368")
        self.input_difop.setValidator(QIntValidator(1, 65535, self))
        self.input_difop.setFixedWidth(40)
        top_layout.addWidget(QLabel("DIFOP:"))
        top_layout.addWidget(self.input_difop)

        top_layout.addSpacing(10)
        self.chk_box = QCheckBox("Show Box")
        self.chk_box.setChecked(True)
        self.chk_box.stateChanged.connect(self.toggle_box)
        top_layout.addWidget(self.chk_box)

        # === ПАНЕЛЬ НАСТРОЙКИ КООРДИНАТ X, Y, Z ===
        top_layout.addSpacing(10)
        top_layout.addWidget(QLabel("X:"))
        self.spin_x = QDoubleSpinBox()
        self.spin_x.setRange(-10.0, 10.0); self.spin_x.setSingleStep(0.05); self.spin_x.setFixedWidth(55)
        self.spin_x.valueChanged.connect(lambda v: self.change_offset('x', v))
        top_layout.addWidget(self.spin_x)

        top_layout.addWidget(QLabel("Y:"))
        self.spin_y = QDoubleSpinBox()
        self.spin_y.setRange(-10.0, 10.0); self.spin_y.setSingleStep(0.05); self.spin_y.setFixedWidth(55)
        self.spin_y.valueChanged.connect(lambda v: self.change_offset('y', v))
        top_layout.addWidget(self.spin_y)

        top_layout.addWidget(QLabel("Z:"))
        self.spin_z = QDoubleSpinBox()
        self.spin_z.setRange(-10.0, 10.0); self.spin_z.setSingleStep(0.05); self.spin_z.setFixedWidth(55)
        self.spin_z.valueChanged.connect(lambda v: self.change_offset('z', v))
        top_layout.addWidget(self.spin_z)

        # === Детектор ===
        self.lbl_detection = QLabel("Rider: 0 pts")
        self.lbl_detection.setStyleSheet("font-weight: bold; color: gray; margin-left: 10px;")
        top_layout.addWidget(self.lbl_detection)

        top_layout.addStretch()

        self.btn_load = QPushButton("Open PCAP")
        self.btn_load.clicked.connect(self.load_file)
        top_layout.addWidget(self.btn_load)
        
        main_layout.addLayout(top_layout)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # === ВКЛАДКА 1: 3D ДВИЖОК VISPY ===
        self.tab_player = QWidget()
        player_layout = QVBoxLayout(self.tab_player)
        self.canvas = scene.SceneCanvas(keys='interactive', show=False, bgcolor='black')
        self.view = self.canvas.central_widget.add_view()
        self.view.camera = 'turntable'
        self.view.camera.distance = 25 
        self.view.camera.elevation = 20
        player_layout.addWidget(self.canvas.native)

        # Инициализация точек и цвета
        self.scatter = visuals.Markers(parent=self.view.scene)
        self.cmap = Colormap(['blue', 'yellow', 'red'])

        # Инициализация прозрачного параллелепипеда (Bounding Box)
        self.box_width = self.roi_max[0] - self.roi_min[0]
        self.box_height = self.roi_max[1] - self.roi_min[1]
        self.box_depth = self.roi_max[2] - self.roi_min[2]
        
        self.roi_visual = visuals.Box(width=self.box_width, height=self.box_height, depth=self.box_depth,
                                      color=(0, 1, 0, 0.15), edge_color=(0, 1, 0, 1), 
                                      parent=self.view.scene)
        self.update_box_transform() # Ставим на начальное место

        # --- НИЖНЯЯ ПАНЕЛЬ ПЛЕЕРА ---
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
        self.lbl_return_mode = QLabel("-"); self.lbl_expected = QLabel("-") 

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
            "Packet #", "System Time", "HW Time", "Sync", 
            "GPS Locks", "Voltage", "Current", 
            "Bot Temp", "Main Temp", "RPM"
        ])
        self.table_difop.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        analysis_layout.addWidget(self.table_difop)

        self.tabs.addTab(self.tab_analysis, "Telemetry")

        self.timer = QTimer()
        self.timer.timeout.connect(self.next_frame)
        self.is_playing = False

    def change_offset(self, axis, value):
        if axis == 'x': self.offset_x = value
        elif axis == 'y': self.offset_y = value
        elif axis == 'z': self.offset_z = value

        self.update_box_transform()
        
        # === ВЫВОД КООРДИНАТ ДЛЯ GO-КОДА ===
        cur_min = self.roi_min + [self.offset_x, self.offset_y, self.offset_z]
        cur_max = self.roi_max + [self.offset_x, self.offset_y, self.offset_z]
        
        print("\n--- NEW ROI COORDINATES (Copy to Go code) ---")
        print(f"MinCoordinates: &robot_rider_detection_proto_msgs.Point{{X: {cur_min[0]:.5f}, Y: {cur_min[1]:.5f}, Z: {cur_min[2]:.5f}}},")
        print(f"MaxCoordinates: &robot_rider_detection_proto_msgs.Point{{X: {cur_max[0]:.5f}, Y: {cur_max[1]:.5f}, Z: {cur_max[2]:.5f}}},")
        print("---------------------------------------------")

        if self.total_frames > 0 and self.parser is not None:
            self.update_frame(self.current_frame)

    def update_box_transform(self):
        # Центр коробки смещается вместе с офсетами
        box_center_x = (self.roi_max[0] + self.roi_min[0]) / 2.0 + self.offset_x
        box_center_y = (self.roi_max[1] + self.roi_min[1]) / 2.0 + self.offset_y
        box_center_z = (self.roi_max[2] + self.roi_min[2]) / 2.0 + self.offset_z
        self.roi_visual.transform = STTransform(translate=(box_center_x, box_center_y, box_center_z))

    def toggle_box(self, state):
        self.roi_visual.visible = (state == Qt.Checked)
        if self.total_frames > 0 and self.parser is not None:
            self.update_frame(self.current_frame)

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
        for row, item in enumerate(difop_data):
            self.table_difop.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            dt = datetime.datetime.fromtimestamp(item["ts"])
            self.table_difop.setItem(row, 1, QTableWidgetItem(dt.strftime('%H:%M:%S.%f')[:-3]))
            self.table_difop.setItem(row, 2, QTableWidgetItem(item["hw_time"]))
            self.table_difop.setItem(row, 3, QTableWidgetItem(f"{item['sync_mode']} | {item['sync_state']}"))
            self.table_difop.setItem(row, 4, QTableWidgetItem(f"{item['pps_lock']}/{item['gprmc_lock']}/{item['utc_lock']}"))
            self.table_difop.setItem(row, 5, QTableWidgetItem(f"{item['voltage']:.2f} V" if item['voltage'] else "N/A"))
            self.table_difop.setItem(row, 6, QTableWidgetItem(f"{item['current']:.2f}" if item['current'] else "N/A"))
            self.table_difop.setItem(row, 7, QTableWidgetItem(f"{item['bot_fpga_temp']}"))
            self.table_difop.setItem(row, 8, QTableWidgetItem(f"{item['main_bot_temp']}/{item['main_fpga_temp']}"))
            self.table_difop.setItem(row, 9, QTableWidgetItem(str(item['realtime_rpm'])))
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
        
        # Обновление статистики пакетов
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
            self.lbl_frame_stats.setText(f"MSOP Pkts: <span style='color:{color}'>{msop_count}</span> / {expected}")
        
        frame_data = self.cache.get(frame_id)
        if frame_data is None:
            frame_data = self.parser.load_frame(frame_id)
            self.cache.put(frame_id, frame_data)
        if frame_data is None or len(frame_data) == 0: return

        xyz = frame_data[:, :3]
        intensity = frame_data[:, 3]

        intensity_norm = np.clip(intensity / 255.0, 0.0, 1.0)
        colors = self.cmap.map(intensity_norm)

        # === ЛОГИКА ДЕТЕКТОРА (с учетом текущих смещений) ===
        cur_min = self.roi_min + [self.offset_x, self.offset_y, self.offset_z]
        cur_max = self.roi_max + [self.offset_x, self.offset_y, self.offset_z]

        in_box = (
            (xyz[:, 0] >= cur_min[0]) & (xyz[:, 0] <= cur_max[0]) &
            (xyz[:, 1] >= cur_min[1]) & (xyz[:, 1] <= cur_max[1]) &
            (xyz[:, 2] >= cur_min[2]) & (xyz[:, 2] <= cur_max[2])
        )
        
        detected_count = np.sum(in_box)

        if detected_count > 0:
            self.lbl_detection.setText(f"Rider: {detected_count} pts [DETECTED]")
            self.lbl_detection.setStyleSheet("font-weight: bold; color: red; margin-left: 10px;")
            if self.chk_box.isChecked():
                colors[in_box] = [1.0, 0.0, 0.0, 1.0] # Красим точки в красный
        else:
            self.lbl_detection.setText("Rider: 0 pts [CLEAR]")
            self.lbl_detection.setStyleSheet("font-weight: bold; color: green; margin-left: 10px;")

        self.scatter.set_data(pos=xyz, face_color=colors, edge_width=0, size=self.point_size)