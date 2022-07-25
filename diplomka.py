from sympy import true
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
# Začátek programu
start_time = time.time()
# Jak dlouho se bude model trénovat
training_time = 10*60

# Output
ring_buffer_file = 'log/pcap-history.pcap'
num_ring_files = 10
ring_file_size = 100000

# Setup
with open('log/settings.yml', 'r') as yamlfile:
    settings = yaml.safe_load(yamlfile)
n_gram_size = settings['N-gram Size']
time_window = settings['Time Window']
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

fig, ax = plt.subplots()
(line,) = ax.plot(np.zeros(8192), lw=2, animated=True)
ax.set_ylim(0, 100)
plt.show(block=False)
plt.pause(0.1)
bg = fig.canvas.copy_from_bbox(fig.bbox)
ax.draw_artist(line)
fig.canvas.blit(fig.bbox)


print('Loading model...')
model = tf.keras.models.load_model('./log/station_model')
print('Model loaded!')
index = 0
sequences = list()
sequence = list(np.zeros(n_gram_size))

type_sequence_plot = collections.deque(np.zeros(8192),maxlen=8192)
frame_num = 0
print('Starting capture')
for packet in capture:
    try:
        pkt_type, source = packet_handler(packet)
    except:
        continue
    sequence.pop(0)
    sequence.append(pkt_type)
    sequences.append(sequence.copy())
    index = (index + 1) % 16
    frame_num = frame_num + 1
    if index == 0:
        result = model.predict(sequences)
        anomaly_score = tf.keras.losses.mse(result.reshape(16, n_gram_size), np.array(sequences).reshape(16, n_gram_size))
        type_sequence_plot.extend(anomaly_score.numpy())
        sequences.clear()
        
        fig.canvas.restore_region(bg)
        line.set_ydata(type_sequence_plot)
        ax.draw_artist(line)
        fig.canvas.blit(fig.bbox)
        fig.canvas.flush_events()
        plt.pause(0.01)