# Generated by Django 4.2.3 on 2023-08-05 08:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app", "0065_alter_video_video_file_alter_video_youtube_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="learner",
            name="avatar",
            field=models.ImageField(blank=True, upload_to="Media/avatar"),
        ),
    ]
