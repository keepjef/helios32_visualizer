import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="Plot MSOP packets from a CSV file.")
    parser.add_argument("csv_file", help="Path to the input .csv file.")
    parser.add_argument("-o", "--output", help="Path to save the plot (e.g., plot.png). If not provided, shows the plot in a window.")
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"Error: File '{args.csv_file}' not found.")
        sys.exit(1)

    try:
        # Read the CSV file
        df = pd.read_csv(args.csv_file, sep=';')

        # Check if the original Russian columns exist in the file
        required_columns_ru = ['Время', 'Получено MSOP', 'Ожидалось MSOP']
        for col in required_columns_ru:
            if col not in df.columns:
                print(f"Error: Missing column '{col}' in the provided CSV file.")
                sys.exit(1)

        # Rename columns to English immediately
        df.rename(columns={
            'Время': 'Time',
            'Получено MSOP': 'Received MSOP',
            'Ожидалось MSOP': 'Expected MSOP'
        }, inplace=True)

        # Parse time and fix midnight rollover issue using the new English column names
        df['Time'] = pd.to_datetime(df['Time'], format='%H:%M:%S')
        day_rollovers = df['Time'] < df['Time'].shift(1)
        df['Time'] += pd.to_timedelta(day_rollovers.cumsum(), unit='D')

        # Setup the plot figure
        plt.figure(figsize=(14, 6))

        # 1. "Received MSOP" line
        plt.plot(df['Time'], df['Received MSOP'], 
                 label='Received MSOP', color='#1f77b4', linestyle='-', linewidth=1.2)

        # 2. "Expected MSOP" line (zorder=3 puts it on top)
        plt.plot(df['Time'], df['Expected MSOP'], 
                 label='Expected MSOP', color='red', linestyle='--', linewidth=1.5, zorder=3)

        # 3. Visual highlight for packet drops
        plt.fill_between(df['Time'], df['Received MSOP'], df['Expected MSOP'], 
                         where=(df['Received MSOP'] < df['Expected MSOP']), 
                         color='red', alpha=0.4, label='Lost Packets', zorder=2)

        # Labels and Title
        plt.title('MSOP Packets (Received vs Expected)', fontsize=15, pad=15)
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Packets Count', fontsize=12)

        # Adjust Y-axis limits
        plt.ylim(bottom=max(0, df['Received MSOP'].min() - 50), top=df['Expected MSOP'].max() + 50)

        # X-axis formatting (Show only Hours:Minutes)
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M')) 
        plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=1))  
        plt.gcf().autofmt_xdate()

        # Grid and Legend setup
        plt.grid(True, linestyle='--', alpha=0.5)
        plt.legend(fontsize=12, loc='lower right')

        plt.tight_layout()

        # Save to file if output argument is provided, else show it
        if args.output:
            plt.savefig(args.output, dpi=300)
            print(f"Plot successfully saved to: {args.output}")
        else:
            plt.show()

    except Exception as e:
        print(f"An unexpected error occurred during processing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()