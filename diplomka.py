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