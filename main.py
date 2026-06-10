import sys
from pathlib import Path

# Принудительно добавляем корень проекта в пути поиска
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication
from viewer.lidar_player import LidarPlayer

def main():
    app = QApplication(sys.argv)
    
    # Теперь плеер запускается "пустым", файл выбирается внутри
    player = LidarPlayer()
    player.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()