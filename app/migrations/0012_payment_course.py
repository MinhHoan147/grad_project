# Generated by Django 4.1.5 on 2023-01-28 08:35

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0011_payment'),
    ]

    operations = [
        migrations.AddField(
            model_name='payment',
            name='course',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.course'),
        ),
    ]