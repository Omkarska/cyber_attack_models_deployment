import tensorflow as tf
import numpy as np

# Load the SQL Injection model
sql_model = tf.keras.models.load_model('./mymodel.h5')

# Define the function to convert a sentence to character indices for SQL Injection
def data2char_index(X, max_len=1000):
    alphabet = " abcdefghijklmnopqrstuvwxyz0123456789-,;.!?:'\"/\\|_@#$%^&*~`+-=<>()[]{}"
    result = []
    for data in X:
        mat = []
        for ch in data:
            ch = ch.lower()
            if ch not in alphabet:
                continue
            mat.append(alphabet.index(ch))
        result.append(mat)
    X_char = tf.keras.preprocessing.sequence.pad_sequences(np.array(result, dtype=object), padding='post',
                                                           truncating='post', maxlen=max_len)
    return X_char

# Function to make a prediction on a custom input sentence for SQL Injection
def predict_sql_injection(sentence):
    processed_sentence = data2char_index([sentence])
    prediction = sql_model.predict(processed_sentence)
    label = 1 if prediction[0] > 0.5 else 0
    return label, prediction[0][0]
