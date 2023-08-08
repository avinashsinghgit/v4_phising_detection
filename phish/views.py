from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, HttpResponse
# Create your views here.


def index(request):
    return render(request,"index.html")

def about(request):
    return HttpResponse("this is About Page")

def ip(url):
    try:
        ip_check = url.split("//")[1].split("/")[0]  # extracts the domain
        if (ip_check.replace('.','').replace(':','').isnumeric() == True):    # checks whether the domain name contains only numerical values
            return -1
        if (ip_check.replace('.', '').replace(':','').isalnum() == True):         # to check in case of hexadecimal IP address value
            return -1
        else:
            return 1
    except:
        return -1


def search(request):
    if request.method == "POST":
        query = request.POST['q']  # Get the 'query' parameter from the URL
        print(query)
        print("phish to be upcoming")
        
        results = ip(query)  # Call the Python function to process the query
        print(results)

        if results == -1:
            dict_output = {"Result" : "Phising"}
        elif results == 0:
            dict_output = {"Result" : "Suspicious"}
        else:
            dict_output = {"Result" : "Legitmate"}

        return render(request, "result.html", {'results':dict_output})
    
    return render(request, 'search.html')




