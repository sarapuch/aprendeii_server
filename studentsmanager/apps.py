from django.apps import AppConfig


class StudentsmanagerConfig(AppConfig):
    name = 'studentsmanager'
    def ready(self):
        from scheduler import scheduler
        scheduler.start()
