# Generated by Django 3.1.7 on 2022-04-22 03:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authoringtool', '0006_configvalues'),
    ]

    operations = [
        migrations.AlterField(
            model_name='configvalues',
            name='typeI',
            field=models.IntegerField(default=3),
        ),
        migrations.AlterField(
            model_name='configvalues',
            name='typeIII',
            field=models.IntegerField(default=1),
        ),
    ]
