from datetime import datetime
from django import db
from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore, register_events
from django.utils import timezone
from django_apscheduler.models import DjangoJobExecution
import sys, requests
from studentsmanager.models import Keywords_State, Student, Trace, State

#FUNCION PERIODICA: llamada a funcion de studentsmanager
def deactivate_expired_accounts():
    url = 'http://193.146.210.19:8000/accounts/telegram/execute_task/'
    requests.get(url)

#INICIO DE SCHEDULER
def start():
    scheduler = BackgroundScheduler()
    scheduler.remove_all_jobs()
    scheduler.add_jobstore(DjangoJobStore(), "default")
    
    #se ejecuta la funcion cada dia
    scheduler.add_job(deactivate_expired_accounts, 'interval',hours = 24, minutes = 00, seconds = 00)
    register_events(scheduler)
    scheduler.start()
    
    print("Scheduler started...", file=sys.stdout)