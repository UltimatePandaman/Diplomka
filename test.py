import yaml
import pyshark
import os
import time
import asyncio

import pyformulas as pf

import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import collections
# Output
ring_buffer_file = 'log/pcap-history.pcap'
num_ring_files = 10
ring_file_size = 100000

# Setup
with open('log/settings.yml', 'r') as yamlfile:
    settings = yaml.safe_load(yamlfile)
n_gram_size = settings['N-gram Size']
time_window = settings['Time Window']
stations = settings['Stations']
batch_size = 16
type_fifo = [0]*n_gram_size
occurence_fifo = [0]*time_window

capture = pyshark.FileCapture('zbynek-licka-data-hping.pcap')

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

def detect(sequences):
    pass

async def main():
    # Semafory
    dos_lock = asyncio.Lock()
    type_lock = asyncio.lock()
    # Fronty
def redraw_figure():
    plt.gcf().canvas.flush_events()
    plt.show(block=False)

# Model
station_model = tf.keras.models.load_model('./log/station_model')
dos_model = tf.keras.models.load_model('./log/dos_model')

plt.rcParams["figure.figsize"] = [9, 9]
plt.rcParams["figure.autolayout"] = True
fig, axs = plt.subplots(len(stations) + 1)

axs[0].title.set_text('Množství rámců')
text = axs[0].text(
        0.5, 0,
        "Zpoždění: ",
        size=14, ha='center', va='bottom',
        animated=True,
        color='red',
        horizontalalignment='left',
        verticalalignment='center',
        transform=axs[0].transAxes,
        bbox=dict(facecolor='red', alpha=0.5),
        zorder=1)
i = 1
for station in stations:
    axs[i].title.set_text(station)
    i = i + 1
lines = list()
(dos_line,) = axs[0].plot(np.zeros(1800), lw=2, animated=True)
lines.append(dos_line)
for i in range(1,len(stations)+1):
    (line,) = axs[i].plot(np.zeros(8192), lw=2, animated=True)
    lines.append(line)
plt.show(block=False)
plt.pause(0.1)
axs_bgs = list()
for i in range(len(stations)+1):
    axs_bgs.append(fig.canvas.copy_from_bbox(axs[i].bbox))
for i in range(len(stations)+1):
    axs[i].draw_artist(lines[i])
fig.canvas.blit(fig.bbox)

index = 0
station_sequences = dict()
type_sequence_plot = dict()
for station in stations:
    station_sequences[station] = [collections.deque(np.zeros(n_gram_size),maxlen=n_gram_size), collections.deque(maxlen=64)]
    type_sequence_plot[station] = collections.deque(np.zeros(8192),maxlen=8192)

management_count = 0.0
control_count = 0.0
data_count = 0.0
count_sequence = list([[0.0,0.0,0.0]]*60)
type_count_plot = collections.deque(np.zeros(1800),maxlen=1800)
current_time = 0.0
current_interval = 1.0
print('Starting capture')
# Začátek detekce
start_time = time.time()
for packet in capture:
    try:
        pkt_type, source = packet_handler(packet)
    except:
        continue

    current_time = float(packet.frame_info._all_fields['frame.time_relative'])
    if np.floor(current_time) == current_interval:
        current_interval = current_interval + 1.0

        count_sequence.pop(0)
        count_sequence.append([management_count, control_count, data_count])
        result = dos_model.predict([count_sequence])
        anomaly_score = tf.keras.losses.mse(result.reshape(1, time_window*3), np.array(count_sequence).reshape(1, time_window*3))
        type_count_plot.append(float(anomaly_score))

        management_count = 0.0
        control_count = 0.0
        data_count = 0.0

        lines[0].set_ydata(type_count_plot)
        axs[0].set_ylim(0, max(type_count_plot))
        for ax,i in zip(axs, range(len(axs))):
            fig.canvas.restore_region(axs_bgs[i])
            if i == 0:
                text.set_text(f'Zpoždění: {time.time() - start_time - current_interval}')
                ax.draw_artist(text)
            ax.draw_artist(lines[i])
            fig.canvas.blit(ax.bbox)
        fig.canvas.flush_events()
        management_count = management_count + 1.0
    elif pkt_type < 32.0:
        control_count = control_count + 1.0
    elif pkt_type < 48.0:
        data_count = data_count + 1.0

    if not source in stations:
        continue
    station_sequences[source][0].popleft()
    station_sequences[source][0].append(pkt_type)
    station_sequences[source][1].append(station_sequences[source][0].copy())
    index = stations.index(source) + 1
    if len(station_sequences[source][1]) == 64:
        result = station_model.predict(np.array(station_sequences[source][1]))
        anomaly_score = tf.keras.losses.mse(result.reshape(64, n_gram_size), np.array(station_sequences[source][1]).reshape(64, n_gram_size))
        type_sequence_plot[source].extend(anomaly_score.numpy())
        station_sequences[source][1].clear()
        
        lines[index].set_ydata(type_sequence_plot[source])
        axs[index].set_ylim(0, max(type_sequence_plot[source]))
        for ax,i in zip(axs, range(len(axs))):
            fig.canvas.restore_region(axs_bgs[i])
            if i == 0:
                text.set_text(f'Zpoždění: {time.time() - current_interval}')
                ax.draw_artist(text)
            ax.draw_artist(lines[i])
            fig.canvas.blit(ax.bbox)
        fig.canvas.flush_events()