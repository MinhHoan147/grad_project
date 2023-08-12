# Generated by Django 4.2.3 on 2023-08-05 08:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app", "0066_learner_avatar"),
    ]

    operations = [
        migrations.AlterField(
            model_name="learner",
            name="avatar",
            field=models.ImageField(
                default="Media/avatar/default_avatar.png", upload_to="Media/avatar"
            ),
        ),
    ]
