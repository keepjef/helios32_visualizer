import numpy as np
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QSlider, QLabel, QLineEdit, QFileDialog, 
                               QApplication, QSpinBox)
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

        # Настройки воспроизведения и отображения
        self.base_interval = 100
        self.speed_multiplier = 1.0 
        self.point_size = 2  # Базовый размер точек

        self.setWindowTitle("Helios Lidar Player (Pro Edition)")
        self.resize(1280, 720)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # --- ВЕРХНЯЯ ПАНЕЛЬ: НАСТРОЙКИ И ЗАГРУЗКА ---
        top_layout = QHBoxLayout()
        
        # 1. Порт
        lbl_port = QLabel("UDP Port:")
        top_layout.addWidget(lbl_port)
        
        self.input_port = QLineEdit("2368")
        self.input_port.setValidator(QIntValidator(1, 65535, self))
        self.input_port.setFixedWidth(60)
        top_layout.addWidget(self.input_port)

        # 2. Размер точек
        lbl_size = QLabel("Point Size:")
        top_layout.addWidget(lbl_size)

        self.spin_size = QSpinBox()
        self.spin_size.setRange(1, 20)  # Ограничение размера от 1 до 20
        self.spin_size.setValue(self.point_size)
        self.spin_size.setFixedWidth(50)
        self.spin_size.valueChanged.connect(self.change_point_size)
        top_layout.addWidget(self.spin_size)

        # 3. Кнопка загрузки
        self.btn_load = QPushButton("Open PCAP / PCAPNG")
        self.btn_load.clicked.connect(self.load_file)
        top_layout.addWidget(self.btn_load)
        
        top_layout.addStretch()
        layout.addLayout(top_layout)

        # --- 3D ДВИЖОК VISPY ---
        self.canvas = scene.SceneCanvas(keys='interactive', show=False, bgcolor='black')
        self.view = self.canvas.central_widget.add_view()
        self.view.camera = 'turntable'
        self.view.camera.distance = 50 
        self.view.camera.elevation = 30
        layout.addWidget(self.canvas.native)

        self.scatter = visuals.Markers(parent=self.view.scene)

        # Кастомная карта цветов (Синий -> Желтый -> Красный)
        self.cmap = Colormap(['blue', 'yellow', 'red'])

        # --- НИЖНЯЯ ПАНЕЛЬ: ВОСПРОИЗВЕДЕНИЕ И СКОРОСТЬ ---
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

        layout.addLayout(control_layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.next_frame)
        self.is_playing = False

    def change_point_size(self, value):
        self.point_size = value
        # Если файл загружен, мгновенно перерисовываем текущий кадр с новым размером
        if self.total_frames > 0 and self.parser is not None:
            self.update_frame(self.current_frame)

    def change_speed(self, factor):
        self.speed_multiplier *= factor
        # Ограничиваем скорость от 0.25x до 4.0x
        self.speed_multiplier = max(0.25, min(4.0, self.speed_multiplier))
        self.lbl_speed.setText(f"{self.speed_multiplier}x")
        
        if self.is_playing:
            new_interval = int(self.base_interval / self.speed_multiplier)
            self.timer.setInterval(new_interval)

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "*.pcap *.pcapng")
        if not filename: return

        if self.is_playing: self.toggle_play()

        port = self.input_port.text()
        self.setWindowTitle(f"Helios Lidar Player - Loading... [{filename}]")
        QApplication.processEvents()

        index = FrameIndex(filename, port=port)
        index.load_or_build()

        self.parser = HeliosParser(filename, index, port=port)
        self.cache = FrameCache(max_size=50)
        self.total_frames = index.frame_count()

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

        frame_data = self.cache.get(frame_id)
        if frame_data is None:
            frame_data = self.parser.load_frame(frame_id)
            self.cache.put(frame_id, frame_data)

        if frame_data is None or len(frame_data) == 0:
            return

        xyz = frame_data[:, :3]
        intensity = frame_data[:, 3]

        intensity_norm = np.clip(intensity / 255.0, 0.0, 1.0)
        colors = self.cmap.map(intensity_norm)

        # Используем параметр self.point_size для отрисовки
        self.scatter.set_data(
            pos=xyz, 
            face_color=colors, 
            edge_width=0, 
            size=self.point_size
        )