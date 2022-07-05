from django.urls import path

from . import views

app_name = 'usersmanager'

urlpatterns = [
    path('user_data/', views.UserDataView.as_view(), name='user_data'),
    path('edit_user_data/<int:id>', views.EditUserDataView.as_view(), name='edit_user_data'),
    path('password_change/', views.change_password, name='password_change'),
    path('login/', views.LoginView.as_view(), name='login_as_teacher'),
    path('signup/', views.SignUp.as_view(), name='signup_as_teacher'),
    path('reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('activate/<uidb64>/<token>/',views.activate, name='activate'),
    path('students_list_pl/<playlist_id>', views.StudentsListViewPlaylist.as_view(), name='students_list_playlist'),
    path('students_list/<playlist_id>/<mc_id>', views.StudentsListView.as_view(), name='students_list'),
    path('export_all/<user>/<playlist_id>', views.export_all, name='export_all'),
    path('view_traces_all/<user>/<playlist_id>', views.ViewGeneralTraces.as_view(), name='view_all_traces'),
    path('export/<user>/<mc_id>', views.export, name='export'),
    path('view_comments/', views.viewCommentsView.as_view(), name='viewcomments'),
    path('view_comments/<user>', views.viewCommentsperStudentView.as_view(), name='view_comments_per_student'),
    path('view_traces/<user>/<mc_id>', views.ViewTracesView.as_view(), name='view_traces')
]