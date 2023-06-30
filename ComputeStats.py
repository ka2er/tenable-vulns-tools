import os
import sys
from pathlib import Path
import pandas
import sqlite3
import yaml

# requirements : openpyxl
# powerbi : http://www.ch-werner.de/sqliteodbc/ ==> perm denied

#
# TODO nb hosts
# tenable cron > script api > rapports csv/xls > script db historiue > pbi > courbes

currentDirectory = os.path.dirname(os.path.realpath(__file__))

# load config settings
config = yaml.safe_load(open(currentDirectory+"/config.yml"))

path = currentDirectory+"/"+config.get("output_folder")

# open or init sqlite file
conn = sqlite3.connect(path+"/vulns-stats-v1.db")

# create table if needed
sql_init = "CREATE TABLE IF NOT EXISTS vulns_stats (zone txt, target_type txt, nb_high INTEGER, nb_critical INTEGER, nb_assets INTEGER, date DATE, UNIQUE(zone,target_type,date));"
conn.execute(sql_init)
conn.commit()

# list report files
for x in Path(path).rglob( '*xlsx' ):
    # Prints only text file present in My Folder
    print(x)
    file_base = os.path.basename(x)
    if(file_base.count('-') == 5):
        [computer, zone, system, year, month, day] = file_base.split('.')[0].split('-')
    else:
        [computer, zone, year, month, day] = file_base.split('.')[0].split('-')

    try:
        # open file
        df = pandas.read_excel(x, sheet_name="All Vulnerabilities")

        # foreach report file open/parse/count by vuln criticity
        # col C = severity
        # col D = severity_id
        group = df.value_counts(subset=['severity'], sort=False)

        high = group['high']
        critical = group['critical']

        nb_assets = 0

        print(f"computer={computer} zone={zone} {year}-{month}-{day} nb_high={high} nb_critical={critical}")

    except:
        e = sys.exc_info()[0]
        print(f"skipping {x} : {e}")

    # update DB 
    sql_update = f"INSERT INTO vulns_stats (zone, target_type, nb_high, nb_critical, nb_assets, date) VALUES('{zone}', '{computer}', {high}, {critical}, {nb_assets}, date('{year}-{month}-{day}')) ON CONFLICT(zone, target_type, date) DO UPDATE SET nb_high={high}, nb_critical={critical};"
    conn.execute(sql_update)

conn.commit()
conn.close()