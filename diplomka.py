import yaml
import pyshark
import os
import time
import asyncio

import pyformulas as pf

import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
plt.style.use('matplotlib-stylesheets/style.mplstyle')
import collections

# Setup
with open('log/settings.yml', 'r') as yamlfile:
    settings = yaml.safe_load(yamlfile)
n_gram_size = settings['N-gram Size']
time_window = settings['Time Window']
stations = settings['Stations']

def resolve_addresses(pkt):
    ds = int(pkt.wlan._all_fields['wlan.fc.ds'], 16)
    source = 'missing'
    if ds == 0:
        source = pkt.wlan._all_fields['wlan.ta']
    else:
        source = pkt.wlan._all_fields['wlan.sa']
    return source

def packet_handler(pkt):
    source = 'missing'
    try:
        source = resolve_addresses(pkt)
    except:
        pass
    pkt_type = float.fromhex(pkt.wlan._all_fields['wlan.fc.type_subtype'])
    return pkt_type, source

async def sniffer(count_sequence, stations_sequences):
    global stations
    global n_gram_size
    station_sequence = dict()
    for station in stations:
        station_sequence[station] = collections.deque(np.zeros(n_gram_size) ,maxlen=n_gram_size)
    management_count = 0.0
    control_count = 0.0
    data_count = 0.0
    capture = pyshark.FileCapture('zbynek-licka-data-hping.pcap')
    # Online záchyt rámců
    for packet in capture:
        # Pokud je rámec IEEE 802.11, tak vrátí jeho typ a odesilatele. Jinak není IEEE 802.11
        try:
            pkt_type, source = packet_handler(packet)
        except:
            continue
        
        # Čas záchytu je delší než aktuální interval
        if float(packet.frame_info._all_fields['frame.time_relative']) >= current_interval:
            current_interval = current_interval + 1.0
            #DoS modelu se zašlou data na zpracování
            #Thread safe operace
            count_sequence.append([management_count, control_count, data_count])

            management_count = 0.0
            control_count = 0.0
            data_count = 0.0
        # Počet typů rámců v intervalu se zvýší
        if pkt_type < 16.0:
            management_count = management_count + 1.0
        elif pkt_type < 32.0:
            control_count = control_count + 1.0
        elif pkt_type < 48.0:
            data_count = data_count + 1.0
        # Pokud je stanice v settings zpracuje se typ rámce
        if source in stations:
            station_sequence[source].append(pkt_type)
            stations_sequences[source].append(station_sequence[source].copy())



async def main():
    global stations
    count_sequence = collections.deque()
    stations_sequences = dict()
    for station in stations:
        stations_sequences[station] = collections.deque()
    task1 = asyncio.create_task(sniffer(count_sequence, stations_sequences))
    asyncio.sleep(1)
    print(count_sequence, flush=True)
    print(stations_sequences, flush=True)
    await task1

asyncio.run(main())