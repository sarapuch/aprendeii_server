# Generated by Django 3.1.7 on 2022-02-18 10:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authoringtool', '0004_auto_20220210_0641'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='microcontent',
            name='keywords',
        ),
        migrations.AddField(
            model_name='microcontent',
            name='keywords',
            field=models.CharField(default='needtochange', max_length=50),
        ),
    ]
