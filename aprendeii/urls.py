from django.contrib import admin
from django.urls import path, include
import studentsmanager.views as studentsmanager_views
#import authoringtool.views as authoringtool_views

# API
#from rest_framework import routers
#from rest_framework.urlpatterns import format_suffix_patterns

#router = routers.DefaultRouter()
#router.register(r'units', mc_views.UnitViewSet)
#router.register(r'users', usersmanager_views.UserViewSet)
# router.register('^units/{unit}/$', mc_views.unit_detail, basename="unit-detail")

urlpatterns = [
    path('', studentsmanager_views.LoginView.as_view(), name='login'),
    #path('api/', include(router.urls)),
    #path('units/', authoringtool_views.UnitList.as_view()),
    #path('units/<str:unit>/', authoringtool_views.UnitDetail.as_view()),
    path('authoringtool/', include('authoringtool.urls')),
    path('admin/', admin.site.urls),
    path('user_page/', studentsmanager_views.HomeView.as_view(), name='user_page'),
    path('accounts/', include('studentsmanager.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('usersmanager/', include('usersmanager.urls')),
    path('ebisu/', include('ebisu_api.urls')),
    #path('authoringtool', authoringtool_views.microcontent, name='authoringtool'),
]
