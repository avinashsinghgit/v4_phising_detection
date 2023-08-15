# Create your views here.
from django.shortcuts import render, HttpResponse
# Create your views here.

from joblib import dump
import os
import pickle


import re
import pandas as pd
import numpy as np


import whois
import datetime

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# HTML and Javascript Based Features
import warnings

# Domain based features
import whois
from datetime import datetime

# Normalization
from sklearn.preprocessing import MinMaxScaler

# Training
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.model_selection import KFold
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, precision_score, recall_score, ConfusionMatrixDisplay
 

# ###############********************* EDA *******************############

df = pd.read_csv("/Users/avinash/Desktop/phising_dataset.csv").iloc[:,1:]
for col in df.columns:
    unique_value_list = df[col].unique()
    if len(unique_value_list) > 10:
        print(f'{col} has {df[col].nunique()} unique values')
    else:
        print(f'{col} contains:\t\t\t{unique_value_list}')
        
def binary_classification_accuracy(actual, pred):
    
    print(f'Confusion matrix: \n{confusion_matrix(actual, pred)}')
    print(f'Accuracy score: \n{accuracy_score(actual, pred)}')
    print(f'Classification report: \n{classification_report(actual, pred)}')
    
# Replacing -1 with 0 in the target variable
df['Result'] = np.where(df['Result']==-1, 0, df['Result'])
target = df['Result']
features = df.drop(columns=['Result'])

folds = KFold(n_splits=4, shuffle=True, random_state=42)

train_index_list = list()
validation_index_list = list()

for fold, (train_idx, validation_idx) in enumerate(folds.split(features, target)):
    model = XGBClassifier()
    model.fit(np.array(features)[train_idx,:], np.array(target)[train_idx])
    predicted_values = model.predict(np.array(features)[validation_idx,:])
    print(f'==== FOLD {fold+1} ====')
    binary_classification_accuracy(np.array(target)[validation_idx], predicted_values)



# import pickle

# pickle.dump(model, open('model.pkl','wb'))

