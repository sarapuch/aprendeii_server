from multiprocessing import Semaphore
from django.db.models.fields import CharField
from authoringtool.models import Question, MicroContent, Playlist, SortedMicrocontent, ConfigValues
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.forms.models import model_to_dict
from django.contrib.auth.models import User
import sqlite3


class Trace(models.Model):
    microcontent = models.CharField(max_length=200,default='aprendeii')
    action = models.CharField(max_length=2000)
    time = models.DateTimeField('Action time')

class Comments(models.Model):
    comment = models.CharField(default='', max_length=400)
    time = models.DateTimeField('Comment Time')

class State(models.Model):
    microcontent = models.ManyToManyField(MicroContent)
    semaphore = models.CharField(
        max_length=200,
        null=True
    )
    last_update = models.DateTimeField('Last semaphore update')

class Keywords_State(models.Model):
    keyword = models.CharField(max_length=200)
    score = models.IntegerField(default=0)
    semaphore = models.CharField(max_length=200, default='red')
    typeIIx3 = models.IntegerField(default=0)
    typeIIx2 = models.IntegerField(default=0)
    alreadydoneII = models.CharField(max_length=200,default='')
    alreadydoneIII = models.CharField(max_length=200,default='')
    

class Student(User):
    tracking = models.ManyToManyField(Trace)
    states = models.ManyToManyField(State)
    keywords_states = models.ManyToManyField(Keywords_State)
    courses = models.ManyToManyField(Playlist)
    alexa_id = models.CharField(
        max_length=50,
        null=True
    )
    dateofbirth = models.DateField(null=True)
    telegram_id = models.CharField(
        max_length=20,
        blank=True
    )
    itinerary = models.ManyToManyField(SortedMicrocontent)
    current_keyword = models.CharField(max_length=200, default='start')
    notification = models.BooleanField(default=False)
    comments = models.ManyToManyField(Comments)
'''comentario sobre secuencia'''