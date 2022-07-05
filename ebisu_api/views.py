from django.shortcuts import render

# Create your views here.
from django.db import models
import json

from matplotlib.font_manager import json_dump
import ebisu

from .models import Keywords_Model, Student

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.core import serializers

from datetime import timedelta

#COMPROBACION DE VALORES PARA CURVAS DE OLVIDO
def check_values(request, **kwargs):
    username = kwargs['username']
    data = {}
    
    #comprobamos que exista en la base de datos de ebisu_api
    if not Student.objects.filter(username=username).exists():
        data = {}
        data['error'] = 'Not enough data'
        data_json = json.dumps(data)
        return HttpResponse(data_json)

    student = Student.objects.filter(username = username).get()
    keywords_models = student.keywords.order_by('order').all()

    #recorremos modelos de keywords
    for keyword in keywords_models:
        ebisuModel = (keyword.alpha, keyword.beta, keyword.halflife)
        lastTest = keyword.lastTest

        oneHour = timedelta(hours=1)
        diffHours = (timezone.now() - lastTest) / oneHour

        #calculo de porcentaje de olvido
        predictedRecall = ebisu.predictRecall(ebisuModel, diffHours, exact=True)

        if predictedRecall < 0.5:
            data['keyword'] = keyword.keyword
            data_json = json.dumps(data)
            return HttpResponse(data_json)

    #devolvemos mensaje de que no hay nada que repasar
    data['error'] = 'Not enough data'
    data_json = json.dumps(data)
    return HttpResponse(data_json)

#ACTUALIZACION DE MODELO DE EBISU
def update_model(request, **kwargs):
    username = kwargs['username']
    keyword = kwargs['keyword']
    order = kwargs['order']
    success = kwargs['success']
    total = kwargs['total']

    #comprobacion de que exista el usuario
    if not Student.objects.filter(username=username).exists():
        student = Student(username=username)
        student.save()
    student = Student.objects.filter(username=username).get()

    #comprobacion de que existe el modelo asociado a la keyword, en caso contrario se guarda en la base de datos
    if not student.keywords.filter(keyword = keyword).exists():
        keyword = Keywords_Model(keyword = keyword, order = order, alpha=4, beta=4, halflife = 36, lastTest = timezone.now())
        keyword.save()
        student.keywords.add(keyword)
        student.save()

    #si existe la keyword, actualizamos el modelo
    else:
        keywordmodel = student.keywords.filter(keyword=keyword).get()
        ebisuModel = (keywordmodel.alpha, keywordmodel.beta, keywordmodel.halflife)
        lastTest = keywordmodel.lastTest
    
        #calculamos la diferencia de horas entre la ultima fecha y la fecha actual
        oneHour = timedelta(hours=1)
        diffHours = (timezone.now() - lastTest) / oneHour
        
        #llamada a ebisu.updateRecall
        newModel = ebisu.updateRecall(ebisuModel, success, total, diffHours)
        
        #actualizamos los datos
        keywordmodel.alpha = newModel[0]
        keywordmodel.beta = newModel[1]
        keywordmodel.halflife = newModel[2]
        keywordmodel.lastTest = timezone.now()
        keywordmodel.save()

    data = {}
    data['info'] = 'model updated'
    data_json = json.dumps(data)
    return HttpResponse(data_json)


