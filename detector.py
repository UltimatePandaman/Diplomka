import os
os.mkdir('log')
import random
import yaml

import pandas as pd
import numpy as np

import matplotlib.pyplot as plt

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras import layers, losses



"""Generátor n-gramů pro trénování/testování"""
class DataGenerator(tf.keras.utils.Sequence):
    def __resolve_address(self, frame):
        
    '''Generuje data pro keras'''
    def __init__(self, type_list, window_size, batch_size, n_channels):
        'Inicializace'
        self.window_size = window_size
        self.index = 0
        self.batch_size = batch_size
        self.type_list = type_list
        self.n_channels = n_channels
        self.on_epoch_end()

    def __len__(self):
        'Počet batch pro každou epochu'
        return (len(self.type_list)-self.window_size)//self.batch_size - 1

    def __getitem__(self, index):
        'Generuje jeden batch dat'
        X, Y = self.__data_generation()
        return X, Y

    def __conv_features_to_list(self, lst):
        'Vytvoří z 1 featury list'
        return [[el] for el in lst]

    def on_epoch_end(self):
        self.index = 0

    def __data_generation(self):
        'Generuje data obsahující batch_size časových oken'
        X = list()
        for i in range(self.batch_size):
          # Vloží list (sekvence) listů s featurami (každý z těchto listů je samostatný časový okamžik (tj. paket))
          X.append(self.type_list[self.index + i:self.index + i + self.window_size])
        self.index = self.index + self.batch_size
        X = np.array(X)
        return X, X

##Classifier - neuronová síť
#!param[in] input_size Délka sekvence.
#!param[in] n_features Dimenzionalita dat - tj. počet sloupců dat.
#!warning Zkontrolovat, zda inputSize//4 je větší než 0
class Classifier(Model):
    def __init__(self, input_size, n_features):
        super(Classifier, self).__init__()

        # Vrstvy lstm
        self.classifier = tf.keras.Sequential([
        # Encoder
        layers.LSTM(input_size//2, activation='tanh', input_shape=(input_size, n_features), return_sequences=True),
        layers.LSTM(input_size//4, activation='tanh', return_sequences=True),
        # Decoder
        layers.LSTM(input_size//4, activation='tanh', return_sequences=True),
        layers.LSTM(input_size//2, activation='tanh', return_sequences=True),
        layers.TimeDistributed(layers.Dense(n_features, activation='linear'))
        ])

    def call(self, x):
        return self.classifier(x)

## Abstrakce komunikace běžné stanice
# n_grams - sekvence typů rámců po sobě zaslaných v komunikaci
class Station:
    def __init__(self, station_mac, feature_dim, window):
        if not feature_dim > 0:
            raise ValueError('Feature dimension needs to be larger than 0')
        self.station_mac = station_mac
        self.savefile = f"/log/type-sequence-model"
        self.feature_dim = feature_dim
        self.window = window
        self.loaded = False

    def createModel(self, training_data, batch_size):
        """ Trénování modelu """
        # Inicializace
        model = Classifier(self.window, self.features_dim)
        # Parameters
        params = {'window_size': self.window,
                'batch_size': batch_size,
                'n_channels': self.feature_dim}
        # Inicializace generátoru
        training_generator = DataGenerator(training_data, **params)
        # Kompilace
        model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001), loss=losses.MeanSquaredError())
        # Trénování
        model.fit(x=training_generator,epochs=10, verbose=1)  # callbacks=[tensorboard_callback]
        # Uložení modelu
        model.save(self.savefile)
        self.loaded = True

    # Načte model z paměti pokud je dostupný, pokud ne, skončí chybou
    def __load_model(self):
        self.model = tf.keras.models.load_model(self.savefile)

    # Vrátí rekonstruovaná data, které lze dále zpracovávat (vypočítat anomaly score)
    def predict(self, data):
        if self.loaded == False:
            self.__load_model()
        return self.model.predict(data)
        
    # Vrátí rekonstruovaná data a spočítá jejich anomaly score
    def score(self, data):
        if self.loaded == False:
            self.__load_model()
        result = self.model.predict(data)
        return tf.keras.losses.mse(result.reshape(result.shape[0], result.shape[1]*self.feature_dim), data.reshape(data.shape[0], data.shape[1].self.feature_dim))
        
    def __addModel(self, model):
        self.model = model