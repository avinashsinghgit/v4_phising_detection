from django.contrib import admin
from django.urls import path
from phish import views



urlpatterns = [
path("", views.index, name="index"),
path("home/", views.home, name="home"),
path("search/", views.search, name="search"),
path("report_phish/", views.report, name="report")
]
 
 