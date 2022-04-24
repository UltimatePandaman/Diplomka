#---------------------------------------------------#
#                                                   #
#                Diplomová práce                    #
#       Detekce anomálií ve Wi-Fi komunikaci        #
#                                                   #
#                 Zbyněk Lička                      #
#                     2022                          #
#                                                   #
#---------------------------------------------------#

#TODO: import funkcí, které budou transformovat data

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn import preprocessing

import sys
import json

from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model
from tensorflow.keras import layers, losses

# Vlastní knihovna
import datatransformation as dt

#Výstupní soubory
#TODO: jako argumenty jinak default
fdata = open('data.json', 'r', encoding='utf8')

# Načítání dat
data = dt.loadData('data.json')
## List obsahující dosavadní početní zastoupení všech možný typů rámců 802.11 v pcap
# 2D pole
typesList = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            [0,0],
            [0,0],]
dt.requestTypeCounts(data, typesList)

aps = dt.loadAPs(data)
dt.loadStations(data)
dt.setAPFeatures(data, aps)
dt.setStationFeatures(data)

# Načte vybrané featury do listu
ffeatures = open('data_statistics.out', 'r', encoding='utf16')
features = []
for feature in ffeatures.readlines():
    features.append(feature[:-1])

#Slice vybraných sloupců vhodných pro učení klasifikátoru
data = data[features+[
'To AP',
'From AP',
'Destination AP',
'Through AP',
'Station Known',
'Broadcast']]

# Třeba konvertovat hexadecimální hodnoty
dt.convertCols(data, int, 16)
# Převod všech hodnot na float
data = data.astype(float)

print(data.columns[data.isna().any()].tolist())
for col in data.columns[data.isna().any()].tolist():
  data[col].replace(np.nan, 0, inplace=True)

## Normalizace dat na škálu -5 a 5
x = data.values #returns a numpy array
max_abs_scaler = preprocessing.MaxAbsScaler()
x_scaled = max_abs_scaler.fit_transform(x)*5
normalized = pd.DataFrame(np.negative(x_scaled))

x_train, x_test = train_test_split(normalized, test_size=0.2)

##Autoencoder - neuronová síť
#!param[in] inputSize Dimenzionalita dat - tj. počet sloupců dat.
class Autoencoder(Model):
  def __init__(self, inputSize):
    super(Autoencoder, self).__init__()

    self.latent_dim = inputSize#what is this???

    #Encoder. Zahrnuje i prostřední část neuronovky - součást encoding procesu.
    self.encoder = tf.keras.Sequential([
      layers.Flatten(),
      layers.Dense(inputSize/2, activation='relu'),
      layers.Dense(inputSize/4, activation='relu'),
    ])
    #Decoder. Výstup je sigmoid - tj. <-5,5> - tudíž vstup by také měl být maximálně <-5,5>
    self.decoder = tf.keras.Sequential([
      layers.Dense(inputSize/2, activation='relu'),
      layers.Dense(inputSize, activation='sigmoid'),
    ])

  def call(self, x):
    encoded = self.encoder(x)
    decoded = self.decoder(encoded)
    return decoded

#Inicializace neuronové sítě. Vstup je počet dimenzionalita dat - tj. počet sloupců.
autoencoder = Autoencoder(len(data.columns))

#Kompilace
autoencoder.compile(optimizer='adam', loss=losses.MeanSquaredError())

#Trénování a testování
autoencoder.fit(x_train, x_train,
                epochs=10,
                shuffle=True,
                validation_data=(x_test, x_test))

#Zkoušení funkčnosti
#encoded = autoencoder.encoder(x_test).numpy()
#decoded = autoencoder.decoder(encoded).numpy()