from django.urls import path

from . import views

app_name = 'ebisu_api'

urlpatterns = [
    path('check_values/<str:username>/', views.check_values, name='check_values'),
    path('update_model/<str:username>/<str:keyword>/<int:order>/<int:success>/<int:total>', views.update_model, name='update_model')
]