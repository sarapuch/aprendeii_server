# Generated by Django 3.1.7 on 2021-07-05 20:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('studentsmanager', '0003_auto_20210705_2002'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='student',
            name='birthday',
        ),
        migrations.AddField(
            model_name='student',
            name='dateofbirth',
            field=models.DateField(null=True),
        ),
    ]
