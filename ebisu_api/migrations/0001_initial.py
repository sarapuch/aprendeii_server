# Generated by Django 4.0.4 on 2022-06-17 15:06

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Keywords_Model',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('keyword', models.CharField(max_length=200)),
                ('order', models.IntegerField(default=0)),
                ('alpha', models.FloatField(default=4)),
                ('beta', models.FloatField(default=4)),
                ('halflife', models.FloatField(default=24)),
                ('lastTest', models.DateTimeField(verbose_name='date published')),
            ],
        ),
        migrations.CreateModel(
            name='Student',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(default='', max_length=60)),
                ('keywords', models.ManyToManyField(to='ebisu_api.keywords_model')),
            ],
        ),
    ]
