import numpy as np
import pandas as pd
import sys

import json

#Výstupní soubory
fdata = open('data.json', 'r', encoding='utf8')
fstations = open('data_stations.out', 'w')
fAPs = open('data_aps.out', 'w')
#Změna encoding protože proč ne...
sys.stdout.reconfigure(encoding='utf-8')

#Načítání dat
jsonLoad = json.load(fdata)
data = pd.json_normalize(jsonLoad)

#Set float format
pd.set_option('float_format', '{:f}'.format)

#Describe data for statistics
for col in data.columns:
    vals = data.describe()[col].loc[['count', 'unique']]
    print(vals[0])
    print(vals[1])
    print(col)

#Výpis všech stanic v Pcap do data_stations.out - jedná se o známé a důvěryhodné stanice
for station in data['_source.layers.wlan.wlan.ra'].unique():
    fstations.write(station + '\n')

##Následuje vyznačení AP
#Konverze hexadecimální hodnoty typu string na int64
data['_source.layers.wlan.wlan.fc.type_subtype'] = data['_source.layers.wlan.wlan.fc.type_subtype'].apply(int, base=16)
#Probe response a Beacon filtry pro zjištění adres AP
aplist = data[(data['_source.layers.wlan.wlan.fc.type_subtype'] == 8) | (data['_source.layers.wlan.wlan.fc.type_subtype'] == 5)]['_source.layers.wlan.wlan.sa'].unique()
for ap in aplist:
    fAPs.write(ap + '\n')
    #Receiver address
    data.loc[data['_source.layers.wlan.wlan.ra'] == ap, ['To AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.ra'] != ap, ['To AP']] = 0
    #Source address
    data.loc[data['_source.layers.wlan.wlan.sa'] == ap, ['From AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.sa'] != ap, ['From AP']] = 0
    #Transmitter address
    data.loc[data['_source.layers.wlan.wlan.ta'] == ap, ['Through AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.ta'] != ap, ['Through AP']] = 0
    #Destination address
    data.loc[data['_source.layers.wlan.wlan.da'] == ap, ['Destination AP']] = 1
    data.loc[data['_source.layers.wlan.wlan.da'] != ap, ['Destination AP']] = 0


##Rozdělení podle důvěryhodnosti stanice
#Ostatní stanice v tréninku známe
data.loc[data['_source.layers.wlan.wlan.ra'] != 'ff:ff:ff:ff:ff:ff', ['Station Known', 'Broadcast']] = [-5, -5]
#Broadcast receiver address
data.loc[data['_source.layers.wlan.wlan.ra'] == 'ff:ff:ff:ff:ff:ff', ['Station Known', 'Broadcast']] = [-5, -5]

#Slice vybraných sloupců vhodných pro učení klasifikátoru
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

#
#data = data.replace(np.nan, 0)
#data = data.fillna(0)

#data = data.astype(float)