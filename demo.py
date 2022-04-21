import numpy as np
import pandas as pd

import json

fdata = open('data.json', 'r', encoding='utf8')
fstations = open('data_stations.out', 'w')
fAPs = open('data_aps.out', 'w')

jsonLoad = json.load(fdata)
data = pd.json_normalize(jsonLoad)

for station in data['_source.layers.wlan.wlan.ra'].unique():
    fstations.write(station + '\n')

##Následuje vyznačení AP
#Konverze hexadecimální hodnoty typu string na int64
data['_source.layers.wlan.wlan.fc.type_subtype'] = data['_source.layers.wlan.wlan.fc.type_subtype'].apply(int, base=16)
#Probe response a Beacon filtry pro zjištění adres AP
aplist = data[(data['_source.layers.wlan.wlan.fc.type_subtype'] == 8) | (data['_source.layers.wlan.wlan.fc.type_subtype'] == 5)]['_source.layers.wlan.wlan.sa'].unique()
for ap in aplist:
    fAPs.write(ap + '\n')
    #
    data.loc[data['_source.layers.wlan.wlan.ra'] == ap, ['To AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.ra'] != ap, ['To AP']] = 0

    data.loc[data['_source.layers.wlan.wlan.sa'] == ap, ['From AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.sa'] != ap, ['From AP']] = 0

    data.loc[data['_source.layers.wlan.wlan.ta'] == ap, ['Through AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.ta'] != ap, ['Through AP']] = 0

    data.loc[data['_source.layers.wlan.wlan.da'] == ap, ['Destination AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.da'] != ap, ['Destination AP']] = 0


#Ostatní stanice v tréninku známe
data.loc[data['_source.layers.wlan.wlan.ra'] != 'ff:ff:ff:ff:ff:ff', ['Station Known']] = 1
#Broadcast receiver address
data.loc[data['_source.layers.wlan.wlan.ra'] == 'ff:ff:ff:ff:ff:ff', ['Station Known']] = 0

print(data.groupby(['_source.layers.wlan.wlan.ra'])['_source.layers.wlan.wlan.ra'].agg(['count']))

data = data[['_source.layers.frame.frame.len',
'_source.layers.frame.frame.time_delta',
'_source.layers.radiotap.radiotap.version',
'_source.layers.radiotap.radiotap.pad',
'_source.layers.radiotap.radiotap.length',
'To AP',
'From AP',
'Destination AP',
'Through AP',
'Station Known',
'_source.layers.wlan.wlan.duration']]

print(data)

#data = data.replace(np.nan, 0)
#data = data.fillna(0)

#data = data.astype(float)