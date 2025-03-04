# Generated by Django 5.0.6 on 2024-07-08 14:02

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("system", "0003_rename_user_company_owner"),
    ]

    operations = [
        migrations.CreateModel(
            name="Certificate",
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
                ("certificate", models.FileField(upload_to="certificates")),
                (
                    "trainee_contract",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="system.trainee_contract",
                    ),
                ),
            ],
        ),
    ]
