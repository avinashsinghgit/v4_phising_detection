from django.contrib import admin
from django.urls import path
from phish import views



urlpatterns = [
path("", views.index, name="index"),
path("about/", views.about, name="about"),
path("search/", views.search, name="search"),
]

