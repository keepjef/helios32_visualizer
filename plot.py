import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="Построение графика пакетов MSOP из CSV файла.")
    parser.add_argument("csv_file", help="Путь к входному .csv файлу")
    parser.add_argument("-o", "--output", help="Путь для сохранения графика (например, plot.png).")
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"Ошибка: Файл '{args.csv_file}' не найден.")
        sys.exit(1)

    try:
        df = pd.read_csv(args.csv_file, sep=';')

        required_columns = ['Время', 'Получено MSOP', 'Ожидалось MSOP']
        for col in required_columns:
            if col not in df.columns:
                print(f"Ошибка: В файле отсутствует колонка '{col}'.")
                sys.exit(1)

        # Парсинг времени и фикс перехода через полночь
        df['Время'] = pd.to_datetime(df['Время'], format='%H:%M:%S')
        day_rollovers = df['Время'] < df['Время'].shift(1)
        df['Время'] += pd.to_timedelta(day_rollovers.cumsum(), unit='D')

        # Настройка холста
        plt.figure(figsize=(14, 6)) # Сделал чуть шире для 8 часов данных

        # 1. Линия "Получено MSOP" (тонкая синяя линия БЕЗ точек)
        plt.plot(df['Время'], df['Получено MSOP'], 
                 label='Получено MSOP', color='#1f77b4', linestyle='-', linewidth=1.2)

        # 2. Линия "Ожидалось MSOP" (красная пунктирная)
        # zorder=3 выводит её поверх синей линии
        plt.plot(df['Время'], df['Ожидалось MSOP'], 
                 label='Ожидалось MSOP', color='red', linestyle='--', linewidth=1.5, zorder=3)

        # 3. Визуальная подсветка потерь (закрашивает промежуток между линиями)
        plt.fill_between(df['Время'], df['Получено MSOP'], df['Ожидалось MSOP'], 
                         where=(df['Получено MSOP'] < df['Ожидалось MSOP']), 
                         color='red', alpha=0.4, label='Потерянные пакеты', zorder=2)

        # Настройка подписей
        plt.title('График пакетов MSOP (Получено vs Ожидалось)', fontsize=15, pad=15)
        plt.xlabel('Время', fontsize=12)
        plt.ylabel('Количество пакетов', fontsize=12)

        # Ограничиваем ось Y чуть выше максимума, чтобы линия не прилипала к потолку
        plt.ylim(bottom=max(0, df['Получено MSOP'].min() - 50), top=df['Ожидалось MSOP'].max() + 50)

        # Форматирование оси X
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M')) # Убрал секунды из подписей оси для чистоты
        plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=1))  # Отсечки каждый час
        plt.gcf().autofmt_xdate()

        # Настройка сетки и легенды
        plt.grid(True, linestyle='--', alpha=0.5)
        plt.legend(fontsize=12, loc='lower right') # Убрал легенду в правый нижний угол, чтобы не мешала линии 1500

        plt.tight_layout()

        if args.output:
            plt.savefig(args.output, dpi=300)
            print(f"График успешно сохранен в: {args.output}")
        else:
            plt.show()

    except Exception as e:
        print(f"Произошла ошибка при обработке: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()