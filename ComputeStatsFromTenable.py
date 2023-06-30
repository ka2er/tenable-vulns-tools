import os
from pathlib import Path
import pandas
import sqlite3
import requests_cache
import json
from datetime import datetime
import yaml

# debug json
import jsbeautifier
opts = jsbeautifier.default_options()
opts.indent_size = 2


# requirements : openpyxl
# powerbi : http://www.ch-werner.de/sqliteodbc/ ==> perm denied
# python : pyyaml

currentDirectory = os.path.dirname(os.path.realpath(__file__))

# load config settings
config = yaml.safe_load(open(currentDirectory+"/config.yml"))

#
# TODO
# + deeper visibility (ok via unarchive)
# - pc zone guess | dump pc tags by zone ..
# + load setting from external config file
# tenable cron > script api > sqlite > pbi > data viz

# prepare authentication payload
headers = {
    'X-ApiKeys': f'accessKey={config.get("tenable").get("access_key")};secretKey={config.get("tenable").get("secret_key")}',
}

## don't negociate TLS each time

# Session Objects
# The Session object allows you to persist certain parameters across requests. It also persists 
# cookies across all requests made from the Session instance, and will use urllib3’s connection pooling.
#  So if you’re making several requests to the same host, the underlying TCP connection will be reused,
#  which can result in a significant performance increase (see HTTP persistent connection).
#session = requests.Session()
urls_expire_after = {
    # "cloud.tenable.com/scans/*/history?limit=50" : 7*60*60,
    "cloud.tenable.com/scans/*/history?limit=50" : requests_cache.DO_NOT_CACHE,
    # "cloud.tenable.com/scans/*?history_id=*" : requests_cache.DO_NOT_CACHE,
    # "cloud.tenable.com/scans/*/unarchive" : requests_cache.DO_NOT_CACHE,
    # "cloud.tenable.com/scans/*/export/*/status" : requests_cache.DO_NOT_CACHE,
    # "/cloud.tenable.com/scans/*/export/*/download" : requests_cache.DO_NOT_CACHE,
    # "cloud.tenable.com/scans/*/export?history_id=*" : requests_cache.DO_NOT_CACHE,
    
}
session = requests_cache.CachedSession(cache_name=f'{currentDirectory}/{config.get("cache_folder")}/stats_cache', urls_expire_after=urls_expire_after, allowable_methods=('GET', 'POST'))


## wrapper to debug json
def json_debug(json_data):
    print(jsbeautifier.beautify(json.dumps(json_data), opts))


path = currentDirectory+"/"+config.get("output_folder")

# open or init sqlite file : local persistance
conn = sqlite3.connect(path+"/vulns-stats.db")

# create table if needed
sql_init = "CREATE TABLE IF NOT EXISTS vulns_stats (zone txt, target_type txt, nb_high INTEGER, nb_critical INTEGER, nb_scans INTEGER, nb_assets INTEGER, date DATE, UNIQUE(zone,target_type,date));"
conn.execute(sql_init)
conn.commit()

# load scands ids from config file
scan_ids = config.get('tenable').get('scan_ids')

def unarchive_scan(scan_id):
    url = f"https://cloud.tenable.com/scans/{scan_id}/unarchive"
    #print(url)
    #payload = {}
    # we need to trick server ... to let us unarchive like we do in web UI
    h = {
        'X-ApiKeys': headers['X-ApiKeys'],
         "accept": "*/*",
         "accept-language": "fr,fr-FR;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "mode": "cors",
        "referrer": "https://cloud.tenable.com/tio/app.html",
    }
    response = session.request("POST", url, data={},headers=h)
    print(response)
    # .json()
    # json_debug(response)

def get_scan_history(scan_id):
    print(f"Get scan history for {scan_id}")

    url = f"https://cloud.tenable.com/scans/{scan_id}/history?limit=50"
    response = session.request("GET", url, headers=headers)

    #json_debug(response.json())
    return response.json().get('history')

def get_scan_stats(scan_id, history_id):
    print(f"Get scan history stats for {scan_id}#{history_id}")

    url = f"https://cloud.tenable.com/scans/{scan_id}?history_id={history_id}"
    #print(url)
    payload = {
    }
    response = session.request("GET", url, headers=headers, data=payload).json()
    #json_debug(response)
    info = response.get('info')
    hosts = response.get('hosts')

    #json_debug(response)
    pd = pandas.DataFrame(hosts)
    #print(hosts)
    #print(hosts[0])

    try:
        max_host_count = {
            "agent" : info.get('agent_count'),
            "remote" : len(info.get('targets').split('\n'))
        }
        return {
            "name" : info.get('name'),
            "nb_hosts" : info.get('hostcount'),
            "max_hosts" : max_host_count.get(info.get('scan_type'), 0),
            "nb_hosts" : info.get('hostcount'),
            "nb_high" : pd['high'].sum(),
            "nb_critical" :  pd['critical'].sum()
        }
    except KeyError as e:
        print(e)
        # # scan is cold ... we need to export it...
        # url = f"https://cloud.tenable.com/scans/{scan_id}/export?history_id={history_id}"

        # payload = { "format": "csv" } # or CSV
        # file_id = response = session.request("POST", url, json=payload, headers=headers).json().get('file')
        # json_debug(file_id)

        # # while retry loop
        # ready = False
        # while not ready:
        #     url = f"https://cloud.tenable.com/scans/{scan_id}/export/{file_id}/status"
        #     status = session.request("GET", url, headers=headers).json().get("status")
        #     json_debug(status)
        #     ready = status == "ready"
        #     if not ready:
        #         time.sleep(2)

        # url = f"https://cloud.tenable.com/scans/{scan_id}/export/{file_id}/download"
        # response = session.request("GET", url, headers=headers)
        # csv = response.text

        # with open(path+"/Output.csv", "w", encoding="utf-8") as text_file:
        #     text_file.write(csv)

        # #pd_report = pandas.read_csv(csv)
        # #print(pd_report)
        # exit()

for scan_id in scan_ids:
    try:
        for scan_history in get_scan_history(scan_id):

            #json_debug(scan_history)

            x_scan_id = scan_history.get('id')
            x_scan_uuid = scan_history.get('scan_uuid')
            x_scan_status = scan_history.get('status') == "completed"
            x_scan_hot = scan_history.get('is_archived') == False
            x_scan_time_start = scan_history.get('time_start')
            x_date = datetime.fromtimestamp(x_scan_time_start).strftime('%Y-%m-%d')

            if not x_scan_hot:
                json_debug(scan_history)
                unarchive_scan(x_scan_uuid)
            
            #x_scan_hot = True #### TO DEBUG - comment to not gather older reports...
            if x_scan_status & x_scan_hot:
                print(f"{scan_id} {x_scan_id} {x_scan_uuid} {x_scan_status} on {x_scan_time_start}")
                stats = get_scan_stats(scan_id, x_scan_id)
                #print(stats)
                #print(config.get('zone_map'))

                x_scan_name = stats['name']
                t_prop = {
                    "zone_map" : "",
                    "type_map": ""
                }
                for prop in t_prop:
                    for x_pattern in config.get(prop):
                        if x_pattern in x_scan_name or x_pattern == "default":
                            t_prop[prop] = config.get(prop).get(x_pattern)
                            break

                # update DB 
                sql_update = f"INSERT INTO vulns_stats (zone, target_type, nb_high, nb_critical, nb_scans, nb_assets, date) VALUES('{t_prop['zone_map']}', '{t_prop['type_map']}', {stats['nb_high']}, {stats['nb_critical']}, {stats['max_hosts']}, {stats['nb_hosts']}, date('{x_date}')) ON CONFLICT(zone, target_type, date) DO UPDATE SET nb_high={stats['nb_high']}, nb_critical={stats['nb_critical']};"
                print(sql_update)
                conn.execute(sql_update)
    except Exception as e:
        print(f"Scan ID:{scan_id} is empty ({e})")
        
conn.commit()
conn.close()