# Generated by Django 4.1.4 on 2023-08-13 06:14

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Report",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("url", models.URLField()),
                ("email", models.EmailField(max_length=254)),
                ("message", models.TextField()),
            ],
        ),
    ]
