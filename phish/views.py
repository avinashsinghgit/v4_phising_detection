from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, HttpResponse
# Create your views here.

from joblib import dump
import os

import pickle



def index(request):
    return render(request,"index.html")

def about(request):
    return HttpResponse("this is About Page")

def ip(url):
    try:
        domain = url.split("//")[1].split("/")[0]  # Extracts the domain
        if domain.replace('.', '').replace(':', '').isnumeric():
            return -1  # If the domain name contains only numerical values
        if domain.isalnum():
            return -1  # To check in case of hexadecimal IP address value
        else:
            return 1
    except:
        return -1


def search(request):


    if request.method == "POST":

        model=pickle.load(open('model.pkl','rb'))
        
        query = request.POST['q']  # Get the 'query' parameter from the URL
        print(query)
        print("phish to be upcoming")
            
        results = ip(query)  # Call the Python function to process the query
        print(results)


        if results == -1:
            dict_output = {"Result" : "Phising"}
        elif results == 0:
            dict_output = {"Result" : "Suspicious"}
        if results == 1:
            dict_output = {"Result" : "Legitmate"}

        return render(request, "result.html", {'results':dict_output})
    
    return render(request, 'search.html')




