import yaml
import pyshark
import time
import collections

import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
plt.style.use('matplotlib-stylesheets/style.mplstyle')

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

capture = pyshark.FileCapture('zbynek-licka-data-hping.pcap')

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

# Model
station_model = tf.keras.models.load_model('./log/station_model')
dos_model = tf.keras.models.load_model('./log/dos_model')

index = 0
station_sequence = dict()
stations_sequences = dict()
type_sequence_plot = dict()
for station in stations:
    station_sequence[station] = collections.deque(np.zeros(n_gram_size),maxlen=n_gram_size)
    stations_sequences[station] = collections.deque(maxlen=64)
    type_sequence_plot[station] = collections.deque(np.zeros(8192),maxlen=8192)

management_count = 0.0
control_count = 0.0
data_count = 0.0
count_sequence = list([[0.0,0.0,0.0]]*60)
type_count_plot = collections.deque(np.zeros(1800),maxlen=1800)
current_time = 0.0
current_interval = 1.0

plt.rcParams["figure.figsize"] = [9, 9]
plt.rcParams["figure.autolayout"] = True
fig, axs = plt.subplots(len(stations) + 1)
axs[0].title.set_text('Množství rámců')
i = 1
for station in stations:
    axs[i].title.set_text(station)
    i = i + 1
lines = list()
(dos_line,) = axs[0].plot(np.zeros(1800), lw=2)
lines.append(dos_line)
for i in range(1,len(stations)+1):
    (line,) = axs[i].plot(np.zeros(8192), lw=2)
    lines.append(line)
fig.canvas.draw()
plt.show(block=False)

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

        fig.canvas.draw()
        fig.canvas.flush_events()
    if pkt_type < 16.0:
        management_count = management_count + 1.0
    elif pkt_type < 32.0:
        control_count = control_count + 1.0
    elif pkt_type < 48.0:
        data_count = data_count + 1.0

    if not source in stations:
        continue
    station_sequence[source].append(pkt_type)
    stations_sequences[source].append(station_sequence[source].copy())
    if len(stations_sequences[source]) == 64:
        index = stations.index(source) + 1
        result = station_model.predict(np.array(stations_sequences[source]))
        anomaly_score = tf.keras.losses.mse(result.reshape(64, n_gram_size), np.array(stations_sequences[source]).reshape(64, n_gram_size))
        type_sequence_plot[source].extend(anomaly_score.numpy())
        stations_sequences[source].clear()

        lines[index].set_ydata(type_sequence_plot[source])
        axs[index].set_ylim(0, max(type_sequence_plot[source]))

        fig.canvas.draw()
        fig.canvas.flush_events()
