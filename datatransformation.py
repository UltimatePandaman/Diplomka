#---------------------------------------------------#
#                                                   #
#                Diplomová práce                    #
#       Detekce anomálií ve Wi-Fi komunikaci        #
#                                                   #
#                 Zbyněk Lička                      #
#                     2022                          #
#                                                   #
#---------------------------------------------------#

import string
import pandas as pd
import sys

import json

# Nastavení float formátu
pd.set_option('float_format', '{:f}'.format)

#Změna encoding protože proč ne... Not in use rn.
#sys.stdout.reconfigure(encoding='utf-8')

## Vyfiltruje featury na základě jejich zastoupení v datech
# @param[in] data Pandas dataFrame s daty paketů
# @param[in] threshold Určuje jak moc musí být zastoupena featura, aby byla zahrnuta do klasifikace
# @return Featury vhodné pro klasifikaci
def filterFeatures(data, threshold):
    # Získání zastoupení featur
    headerDict = {}
    for col in data.describe(include='all').columns:
        headerDict[col] = data.describe(include='all')[col].loc['count']
    # Filtrování featur
    filtered = []
    for record in headerDict:
        if headerDict[record] > threshold:
            filtered.append(record)

    return filtered

## Načte data z data.json a převede do pandas dataFrame
# @param[in] dataFile JSON soubor s pakety
# @return Panda dataFrame s daty paketů
def loadData(dataFile='data.json'):
    fdata = open(dataFile, 'r', encoding='utf8')
    #Načítání dat
    jsonLoad = json.load(fdata)
    return pd.json_normalize(jsonLoad)

## Výpis všech stanic v trénovacím procesu
# @param[in] filename Output soubor pro stanice
# @param[in] data Pandas dataFrame s daty paketů
# Stanice v trénovacím procesu lze považovat za důvěryhodné a známé
def loadStations(data, filename='data_stations.out'):
    fstations = open(filename, 'w')
    #Výpis všech stanic v Pcap do data_stations.out - jedná se o známé a důvěryhodné stanice
    for station in data['_source.layers.wlan.wlan.ra'].unique():
        fstations.write(station + '\n')

## Načte AP v trénovacím procesu a uloží je do souboru
# @param[in] filename Output soubor pro AP
# @param[in] data Pandas dataFrame s daty paketů
# @return List AP
def loadAPs(data, filename='data_aps.out'):
    fAPs = open(filename, 'w')

    #Probe response a Beacon filtry pro zjištění adres AP
    aplist = data[(data['_source.layers.wlan.wlan.fc_tree.wlan.fc.subtype'] == '8') | (data['_source.layers.wlan.wlan.fc_tree.wlan.fc.subtype'] == '5')]['_source.layers.wlan.wlan.sa'].unique()
    for ap in aplist:
        fAPs.write(ap + '\n')
    return aplist

## Nastaví příslušné featury týkající se AP
# @param[in] data Pandas dataFrame s daty paketů
# @param[in] apList List obsahující známé AP
# @after Data mají nové headery popisující komunikaci s AP
def setAPFeatures(data, apList):
    for ap in apList:
        #Receiver address
        data.loc[data['_source.layers.wlan.wlan.ra'] == ap, ['To AP']] = -5
        data.loc[data['_source.layers.wlan.wlan.ra'] != ap, ['To AP']] = 5
        #Source address
        data.loc[data['_source.layers.wlan.wlan.sa'] == ap, ['From AP']] = -5
        data.loc[data['_source.layers.wlan.wlan.sa'] != ap, ['From AP']] = 5
        #Transmitter address
        data.loc[data['_source.layers.wlan.wlan.ta'] == ap, ['Through AP']] = -5
        data.loc[data['_source.layers.wlan.wlan.ta'] != ap, ['Through AP']] = 5
        #Destination address
        data.loc[data['_source.layers.wlan.wlan.da'] == ap, ['Destination AP']] = -5
        data.loc[data['_source.layers.wlan.wlan.da'] != ap, ['Destination AP']] = 5

## Rozdělení podle důvěryhodnosti stanice
# @param[in] data Pandas dataFrame s daty paketů
# @after Data mají nové featury popisující důvěryhodnost stanic
def setStationFeatures(data, training=True):
    if training == True:
        #Ostatní stanice v tréninku známe
        data.loc[data['_source.layers.wlan.wlan.ra'] != 'ff:ff:ff:ff:ff:ff', ['Station Known', 'Broadcast']] = [5, 5]
        #Broadcast receiver address
        data.loc[data['_source.layers.wlan.wlan.ra'] == 'ff:ff:ff:ff:ff:ff', ['Station Known', 'Broadcast']] = [5, 5]

## Konvertuje všechny featury z hexadecimálních hodnot na float/int
# @param[in] data Pandas dataFrame s daty paketů
# @param[in] conversion Na který datový typ se má sloupec konvertovat. float nebo int.
# @param[in] base Jakou bázi má požadovaný sloupec
# @after Příslušné sloupce @data mají své hodnoty změněny na daný datový typ.
def convertCols(data, conversion=int, base=10):
    for col in data.columns:
        if (base == 16) and (type(data[col].unique()[0]) is str):
            try:
                if data[col].unique()[0][:2] == '0x':
                    data[col] = data[col].apply(conversion, base=base)
            except:
                pass
            #data[col] = data[col].apply(conversion, base=base)
        elif base == 10:
            data[col] = data[col].apply(conversion, base=base)

## Přiřadí jednotlivým stanicím počet provedených requestů
# @param[in] data Pandas dataFrame s daty paketů
def requestTypeCounts(data, typesList):
    ## List obsahující dosavadní početní zastoupení všech možný typů rámců 802.11 v pcap
    for index, row in data.iterrows():
        x = int(row['_source.layers.wlan.wlan.fc_tree.wlan.fc.type'])
        y = int(row['_source.layers.wlan.wlan.fc_tree.wlan.fc.subtype'])
        try:
            typesList[x][y] = typesList[x][y] + 1
        except:
            typesList[4][0] = typesList[4][0] + 1

#
#data = data.replace(np.nan, 0)
#data = data.fillna(0)