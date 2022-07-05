from django.urls import path

from . import views

app_name = 'studentsmanager'

urlpatterns = [
    path('user_data/', views.UserDataView.as_view(), name='user_data'),
    path('edit_user_data/<int:id>', views.EditUserDataView.as_view(), name='edit_user_data'),
    path('password_change/', views.change_password, name='password_change'),
    path('login', views.LoginView.as_view(), name='login'),
    path('signup/', views.SignUpActive.as_view(), name='signup'),
    path('reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('activate/<uidb64>/<token>/',views.activate, name='activate'),
    path('courses_list', views.CoursesListView.as_view(), name='courses_list'),
    path('enroll_in_course/<int:course_id>', views.EnrollView.as_view(), name='enroll_in_course'),
    path('choose_itinerary/<int:course_id>', views.ChooseItineraryView.as_view(), name='choose_itinerary'),
    path('send_notification/<int:course_id>/<user>/<str:text>', views.sendNotificationView.as_view(),name='send_notification'),
    path('my_courses', views.MyCoursesView.as_view(), name='my_courses'),
    path('try_playlist/<int:course_id>', views.TryPlaylistView.as_view(), name='try_playlist'),
    path('restart_playlist/<int:course_id>', views.restartCourse.as_view(), name='restart_playlist'),
    path('course_keyword/<int:course_id>', views.CourseKeywordView.as_view(), name='course_keyword'),
    path('get_state_record/<user>/<course>/', views.get_state_record, name='get_state_record'),
    path('get_microcontent_state/<user>/<microcontent>', views.get_microcontent_state, name='get_microcontent_state'),
    path('course_microcontents/<int:course_id>/<str:keyword>', views.CourseMicrocontentsView.as_view(), name='course_microcontents'),
    path('try_microcontent/<int:mc_id>', views.TryMicrocontentView.as_view(), name='try_microcontent'),
    path('try_microcontent/<str:mc_id>', views.TryMicrocontentView.as_view(), name='try_microcontent'),
    path('get_courses/<user>/', views.get_courses, name='get_courses'),
    path('check_alexa/<user>/<str:alexa_id>/', views.check_alexa, name='check_alexa'),
    path('register_alexa/<user>/<str:alexa_id>/<str:birthday>', views.register_alexa, name='register_alexa'),
    path('get_microcontent/<user>/<str:microcontent_id>/', views.get_microcontent, name='get_microcontent'),
    path('get_result/<user>/<str:microcontent_id>/<str:position>/<str:answers>/', views.get_result, name='get_result'),
    path('telegram/execute_task/', views.periodic_task, name="periodic_task"),
    path('telegram/<str:telegram_id>/get_state_record/<course>/', views.get_state_record_telegram, name='get_state_record_telegram'),
    path('telegram/<str:telegram_id>/get_states_keyword/',views.get_states_keyword, name='get_states_keyword'),
    path('telegram/<str:telegram_id>/get_next_microcontent/<course_id>', views.get_next_telegram, name='get_next_telegram'),
    path('telegram/<str:telegram_id>/restart/<course_id>/', views.telegram_restart, name='restart'),
    path('telegram/<str:telegram_id>/get_microcontent/<str:keyword>/<str:level>/', views.get_microcontent_telegram, name='get_microcontent_telegram'),
    path('telegram/<str:telegram_id>/get_result/<str:microcontent_id>/<str:position>/<str:answers>/', views.get_result_telegram, name='get_result_telegram'),
    path('telegram/<str:telegram_id>/get_keywords/', views.get_keywords, name="get_keywords"),
    path('telegram/<str:telegram_id>/activate_notifications/', views.activate_notifications, name="activate_notifications"),
    path('telegram/<str:telegram_id>/comment/<str:comment>/', views.get_comments, name='get_comments')
]
