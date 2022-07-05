# Generated by Django 3.1.7 on 2022-04-22 03:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('studentsmanager', '0007_auto_20220406_0811'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='student',
            name='score',
        ),
        migrations.AddField(
            model_name='keywords_state',
            name='alreadydone',
            field=models.CharField(default='', max_length=200),
        ),
        migrations.AddField(
            model_name='keywords_state',
            name='typeIIx2',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='keywords_state',
            name='typeIIx3',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='student',
            name='current_keyword',
            field=models.CharField(default='start', max_length=200),
        ),
    ]