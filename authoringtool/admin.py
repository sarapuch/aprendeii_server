from django.contrib import admin

from .models import Media, MetaData, Question, MicroContent 

# Register your models here.
admin.site.register(Media)
admin.site.register(MetaData)
admin.site.register(Question)
admin.site.register(MicroContent)