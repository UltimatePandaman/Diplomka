import yaml
import pyshark
import time
import collections

import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
plt.style.use('matplotlib-stylesheets/style.mplstyle')

def packet_handler(pkt):
    pkt_type = float.fromhex(pkt.wlan._all_fields['wlan.fc.type_subtype'])
    return pkt_type

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

# Model
dos_model = tf.keras.models.load_model('./log/dos_model')

management_count = 0.0
control_count = 0.0
data_count = 0.0
count_sequence = list([[0.0,0.0,0.0]]*60)
type_count_plot = collections.deque(np.zeros(1800),maxlen=1800)
current_time = 0.0
current_interval = 1.0

plt.rcParams["figure.figsize"] = [5, 2.5]
plt.rcParams["figure.autolayout"] = True
fig, ax = plt.subplots(1)
ax.title.set_text('Množství rámců')
(dos_line,) = ax.plot(np.zeros(1800), lw=2)
fig.canvas.draw()
plt.show(block=False)

print('Starting capture')
# Začátek detekce
start_time = time.time()
for packet in capture:
    try:
        pkt_type = packet_handler(packet)
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

        dos_line.set_ydata(type_count_plot)
        ax.set_ylim(0, max(type_count_plot))

        fig.canvas.draw()
        fig.canvas.flush_events()
    if pkt_type < 16.0:
        management_count = management_count + 1.0
    elif pkt_type < 32.0:
        control_count = control_count + 1.0
    elif pkt_type < 48.0:
        data_count = data_count + 1.0