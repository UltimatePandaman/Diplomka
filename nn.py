import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model
from tensorflow.keras import layers, losses

import json

fdata = open('data.json', 'r', encoding='utf8')
fheaders = open('data_allheaders.out', 'w')
fcategorical = open('data_categorical.out', 'w')
fnumerical = open('data_numerical.out', 'w')


jsonLoad = json.load(fdata)
data = pd.json_normalize(jsonLoad)

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

latent_dim = 64 

class Autoencoder(Model):
  def __init__(self, latent_dim):
    super(Autoencoder, self).__init__()
    self.latent_dim = latent_dim   
    self.encoder = tf.keras.Sequential([
      layers.Flatten(),
      layers.Dense(latent_dim, activation='relu'),
    ])
    self.decoder = tf.keras.Sequential([
      layers.Dense(65, activation='sigmoid'),
    ])

  def call(self, x):
    encoded = self.encoder(x)
    decoded = self.decoder(encoded)
    return decoded

autoencoder = Autoencoder(latent_dim)

autoencoder.compile(optimizer='adam', loss=losses.MeanSquaredError())

autoencoder.fit(x_train, x_train,
                epochs=10,
                shuffle=True,
                validation_data=(x_test, x_test))

encoded = autoencoder.encoder(x_test).numpy()
decoded = autoencoder.decoder(encoded).numpy()