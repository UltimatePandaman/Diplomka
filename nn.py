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

import sys

from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model
from tensorflow.keras import layers, losses

import json

#Výstupní soubory
#TODO: jako argumenty jinak default
fdata = open('data.json', 'r', encoding='utf8')
fheaders = open('data_allheaders.out', 'w')
fcategorical = open('data_categorical.out', 'w')
fnumerical = open('data_numerical.out', 'w')

#Načítání dat do pandas dataFrame z json. Pcap do JSON lze konvertovat pomocí nástroje Wireshark.
jsonLoad = json.load(fdata)
data = pd.json_normalize(jsonLoad)

#Transformace dat




#Vybrané
data = data[['_source.layers.frame.frame.len',
'_source.layers.frame.frame.time_delta',
'_source.layers.radiotap.radiotap.version',
'_source.layers.radiotap.radiotap.pad',
'_source.layers.radiotap.radiotap.length',]]
'_source.layers.wlan.wlan.duration'

data = data.replace(np.nan, 0)
data = data.fillna(0)

data = data.astype(float)

x_train, x_test = train_test_split(data, test_size=0.2)

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