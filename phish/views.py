from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, HttpResponse
# Create your views here.

from joblib import dump
import os
import pickle


import re
# import requests
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
# import matplotlib.pyplot as plt


# Normalization
from sklearn.preprocessing import MinMaxScaler

# Training
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
# from xgboost import XGBClassifier
from sklearn.tree import DecisionTreeClassifier

from phish_train import *


# import sklearn
# print(sklearn.__version__)



def index(request):
    return render(request,"index.html")

def about(request):
    return HttpResponse("this is About Page")

def report(request):
    return render(request,"report_phish.html")




#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################



def phish(url):
    ########################    Address Bar Based Features    ########################
    
    # ip
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

    # length of url
    def length_url(url):
        try:
            length_of_url = len(url)
            if len(url)<54:
                return 1
            elif len(url)>=54 and len(url)<75:
                return 0
            else:
                return -1
        except:
            return -1

    # shortened_url
    def shortened_url(url):
        try:
            shortened_url_providers = [
                "bit.ly",
                "tinyurl.com",
                "goo.gl",
            ]
            for provider in shortened_url_providers:
                if provider in url:
                    return -1
                else:
                    return 1
        except:
            return -1

        # url = "https://bit.ly/shortened_url"

    # at_url
    def at_url(url):
        try:  
            if "@" in url:
                return -1
            else:
                return 1
        except:
            return -1


    # redirect_url
    def redirect_url(url):
        try:      
            r_url = url.count("//")
            if r_url>1:
                return -1   # redirects to multiple pages
            else:
                return 1    # does not support multiple redirects
        except:
            return -1


    # prefix_suffix (-) seperator
    def prefix_suffix_seperator(url):
        try:      
            domain = url.split("//")[1].split("/")[0]
            if "-" in domain:
                return -1 # has "-" in domain part
            else:
                return 1
        except:
            return -1

    # http://www.Confirme-paypal.com/.


    # subdomain
    def dots_in_domain(url):
        try:   
            dot_count = 0
            domain = url.split("//")[1].split("/")[0]
            for dot_iter in domain:
                if dot_iter == ".":
                    dot_count = dot_count + 1
                else:
                    continue
            if dot_count == 1 : # Legit
                return 1 
            elif dot_count == 2:
                return 0        # Suspesious
            else:
                return -1       # Phising 
        except:
            return -1


    # SSL final state
    def SSLfinal_State(url):
        try:     
            domain = url.split("//")[1].split("/")[0]
            querystring = {"domain": domain}
            headers = {
                "X-RapidAPI-Key": "0db8eab420mshfcb99a069040e32p13b317jsn24ec26c6ba0e",
                "X-RapidAPI-Host": "check-ssl.p.rapidapi.com"
            }
            response = requests.get(url, headers=headers, params=querystring)
            reponse_json = response.json()
            certificate_status = reponse_json['message']
            Age_of_Certificate = reponse_json["lifespanInDays"]
            if certificate_status == "Valid Certificate" and Age_of_Certificate>= 365:
                return 1           # Legit
            if certificate_status == "Valid Certificate" and Age_of_Certificate < 365:
                return 0           # Suspicious
            else:
                return -1          # Phising
        except:
            return -1    # For any other error


    # Domain_registeration_length
    def Domain_registeration_length(url):
        try:
            domain_info = whois.whois(url)
            if domain_info.creation_date:
                expiration_date = domain_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                today = datetime.datetime.now()
                registration_length = (expiration_date - today).days
                if registration_length is not None:
                    if registration_length<=365: # Phising
                        return -1
                    else: 
                        return 1        # Legit
                else: 
                    return -1         # Phising (No Registration length)

            else:
                return -1          # Phising (domain not extracted)

        except Exception as e:
            return -1            # For any error return Phising


    # Favicon
    def is_favicon(url):
        try:
            def get_favicon_url(url):
                try:
                    response = requests.get(url)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.content, 'html.parser')
                    favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
                    if favicon and 'href' in favicon.attrs:
                        favicon_url = favicon['href']
                        favicon_url = urljoin(url, favicon_url)  # Convert to absolute URL if it's a relative URL
                        return favicon_url
                    return 0
                except requests.exceptions.RequestException as e:
        #             print(f"Error fetching URL: {e}")
                    return 0
                except Exception as e:
        #             print(f"Error parsing HTML: {e}")
                    return 0

            domain_url = url
            favicon_url = get_favicon_url(url)

            if favicon_url:
                return 1     # "Favicon is loaded from the domain."
            else:
                return -1      # "Favicon not found or unable to fetch the favicon."
        except:
            return -1          # Any other Error



    # Non-Standard Ports
    def has_non_standard_port(url):
        try: 
            f
            # Regular expression to extract the port number from the URL
            port_regex = r':(\d+)/'

            # List of common service ports
            # common_ports = [80, 443, 21, 22, 23, 25, 110, 143, 993, 995]
            common_ports = [21,22,23,80,443,445,1433,1521,3306,3389]

            # Extract the port number from the URL using the regular expression
            match = re.search(port_regex, url)
            if match:
                port = int(match.group(1))
                if port not in common_ports:
                    return -1  # Phising 

            return 1  # Legit having common ports
        except:
            return -1


    # HTTP in domain
    def http_domain(url):
        try:
            url_list1 = url.split("//")[1] # all thing after "https://" are extracted
            url_list2 = re.split(r"[^a-zA-Z0-9\s]", url_list1) # all things spereated by special chatracters
            com_count = 0
            http_count = 0
            for url_iter in url_list2:
                if (url_iter == "com"): # 1 com is legit but more than 1 is phising
                    com_count = com_count + 1
                elif (url_iter == "http" or url_iter == "https"): # if http or https occurs then it phising
                    http_count = http_count + 1
            if (http_count>0 or com_count>1):
                return -1 # Phising
            else:
                return 1 # Legit       
        except:
            return -1



    ########################    HTML & Javascript Features    ########################

    # No. of Redirect Page    
    def check_redirects(url):
        redirect_count = 0
        try:
            response = requests.get(url, allow_redirects=True)
            if response.history:
                for resp in response.history:
                    redirect_count = redirect_count + 1
            if  redirect_count<=1:
                return 1       # Legit
            elif redirect_count>=2 and redirect_count<4:
                return 0       # Suspicious
            else:
                return -1      # Phising
        except requests.exceptions.RequestException as e:
            return -1

    # url = "https://zipansion.com/3lqqn"


    # Status Bar Customization    
    warnings.filterwarnings("ignore")
    def onmouseover_onmouseout(url):
        try:
            count = 0
            r = requests.get(url,verify=False)
            soup = BeautifulSoup(r.content, 'html5lib') # If this line causes an error, run 'pip install html5lib' or install html5lib
            a_tag = soup.find_all('a')
            for onmouseover_iter in a_tag:
                list1 = re.split(r"[^a-zA-Z0-9\s]", str(onmouseover_iter))
                for list_iter in list1:
                    if ((list_iter.replace(" ", "")) == "onmouseover" or  (list_iter.replace(" ", "")) == "onmouseout"):
                        count = count + 1
                    else:
                        continue
            if count>=1:
                return -1  # Phising
            else:
                return 1  # Legit
        except:
            return -1 # Phising

    # https://www.plus2net.com/javascript_tutorial/status-msg.php    


    # Disabiling Right Click    


    # Using Pop-up Window


    # IFrame Redirection   



    ########################    Domain based Features     ########################    


    # Age of Domain   
    def age_of_domain(url):
        domain = url.split("//")[1].split("/")[0]
        try:
            w = whois.whois(domain)
            # The 'creation_date' can be a list or a single datetime object.
            # If it's a list, we take the first element.
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            current_date = datetime.now()
            age = current_date - creation_date
            if age is not None:
                if age.days>=180:
                    return 1 # Legit
                else:
                    return -1 # Phising
    #             print(f"The age of the domain '{domain_name}' is {age} days.")
            else:
                return -1
    #             print(f"Failed to fetch WHOIS information for '{domain_name}'.")

    #         return age.days
        except Exception as e:
            return -1



    # DNS Record



    # Website Traffic



    # Page Rank



    # Google index
    def google_index(url):
        try:
            google = "https://www.google.com/search?q=site:" + url + "&hl=en"
            response = requests.get(google, cookies={"CONSENT": "YES+1"})
            soup = BeautifulSoup(response.content, "html.parser")
            not_indexed = re.compile("did not match any documents")
            if soup(text=not_indexed):
                return -1  # Phising not Indexed
            else:
                return 1    # Legit Indexed
        except:
            return -1



    # No. of links pointing to Page
    def find_number_of_links(url):
        try:
            # Fetch the HTML content of the page
            response = requests.get(url)

            # Parse the HTML content with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all the anchor tags (links) with 'href' attribute
            links = soup.find_all('a', href=True)

            if len(links) is not None:
                if (len(links) == 0):
                    return -1     # Phising
                elif (len(links)> 0 and len(links)<2):
                    return 0      # Suspicios
                else:
                    return 1        # Legit
            else:
                return -1  # when len(link) is None

        except:
            return -1     # Phising
    

    
    
    ###############********************* Testing *******************############
    input_df = pd.DataFrame(columns = ['having_IPhaving_IP_Address',
                               'URLURL_Length',
                               'Shortining_Service',
                               'having_At_Symbol',
                               'double_slash_redirecting',
                               'Prefix_Suffix',
                               'having_Sub_Domain',
                               'SSLfinal_State',
                               'Domain_registeration_length',
                               'Favicon',
                               'port',
                               'HTTPS_token',
                               'Redirect',
                               'on_mouseover',
                               'age_of_domain',
                               'Google_Index',
                               'Links_pointing_to_page'])


#     url = input("Enter the url addresss : ")
    def features(url):

        input_df = pd.DataFrame()

        input_data_dict = {'having_IPhaving_IP_Address' : ip(url) ,
                           'URLURL_Length' : length_url(url) ,
                           'Shortining_Service' : shortened_url(url) ,
                           'having_At_Symbol' : at_url(url) ,
                           'double_slash_redirecting' : redirect_url(url) ,
                           'Prefix_Suffix' : prefix_suffix_seperator(url) ,
                           'having_Sub_Domain' : dots_in_domain(url) ,
                           'SSLfinal_State' : SSLfinal_State(url) ,
                           'Domain_registeration_length' : Domain_registeration_length(url) ,
                           'Favicon' : is_favicon(url) ,
                           'port' : has_non_standard_port(url) ,
                           'HTTPS_token' : http_domain(url) ,
                           'Redirect' : check_redirects(url) ,
                           'on_mouseover' : onmouseover_onmouseout(url) ,
                           'age_of_domain' : age_of_domain(url) ,
                           'Google_Index' : google_index(url) ,
                           'Links_pointing_to_page' : find_number_of_links(url) ,
                           }

        # print(input_data_dict)

        for key, value in input_data_dict.items():
            input_df = pd.concat([input_df, pd.Series(value, name=key)], axis=1)
        return input_df
    
    input_X_test = features(url)
    output_y_test = rfc.predict(input_X_test)
#     print(output_y_test)

    # if output_y_test is not None:
    #     if output_y_test == -1:
    #         dict_output = {"Result":"Phising Website"}
    #     elif output_y_test == 0:
    #         dict_output = {"Result":"Suspicious Website"}
    #     else:
    #         dict_output = {"Result":"Legitimate Website"}
    # else:
    #     dict_output = {"Result":"Failed to Fetch"}
    
    return output_y_test
    
    





#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################


def search(request):

    if request.method == "POST":

        model = pickle.load(open('model.pkl','rb'))
        
        query = request.POST['q']  # Get the 'query' parameter from the URL
        print(query)
        print("phish to be upcoming")
            
        results = phish(query)  # Call the Python function to process the query
        print(results)

        if results == -1:
            output = "Phising"
        elif results == 0:
            output = "Suspicious"
        else :
            output = "Legitmate"
                
        return render(request, "result.html", {'results':output})
    
    return render(request, 'search.html')






