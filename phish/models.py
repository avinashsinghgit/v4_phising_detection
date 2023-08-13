from django.db import models


# Create your models here.
class Report(models.Model):
    name = models.CharField(max_length=200)
    url = models.URLField()
    email = models.EmailField()
    message = models.TextField()
    def __str__(self):
        return self.name
    
