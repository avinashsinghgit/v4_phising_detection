import re
import requests
import pandas as pd


import whois
import datetime

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# HTML and Javascript Based Features
import warnings

# Domain based features
import whois
from datetime import datetime


# EDA
import matplotlib.pyplot as plt


# Normalization
from sklearn.preprocessing import MinMaxScaler

# Training
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, ConfusionMatrixDisplay

import pickle


###############********************* EDA *******************############

df = pd.read_csv("/Users/avinash/Desktop/phising_dataset.csv").iloc[:,1:]
df1 = df.iloc[:,:-1]
x = df.iloc[:,:-1]
y = df.iloc[:,-1]
scaler=MinMaxScaler()  
scaler.fit(x.values)  
X_scaled=scaler.transform(x.values)   
X_new = pd.DataFrame(X_scaled,columns=x.columns)
X_test,X_train,y_test,y_train = train_test_split(X_new,y,test_size=0.2,random_state=50,shuffle=True,stratify=y)



###############********************* Decision Tree *******************############
# tree = DecisionTreeClassifier(max_depth = 5)
# tree.fit(X_train, y_train)

rfc = RandomForestClassifier()
rfc.fit(X_train, y_train)


y_test_rfc = rfc.predict(X_test)
y_train_rfc = rfc.predict(X_train)
acc_train_rfc = accuracy_score(y_train,y_train_rfc)
acc_test_rfc = accuracy_score(y_test,y_test_rfc)



# pickle.dump(rfc, open('model.pkl','wb'))

