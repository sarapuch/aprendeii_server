# Generated by Django 3.1.7 on 2022-04-01 08:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authoringtool', '0005_auto_20220218_1050'),
        ('studentsmanager', '0005_student_telegram_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='student',
            name='itinerary',
            field=models.ManyToManyField(to='authoringtool.SortedMicrocontent'),
        ),
    ]
