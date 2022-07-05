from django.urls import path

from . import views
from studentsmanager import views as user_views
from django.conf import settings
from django.conf.urls.static import static

app_name = 'authoringtool'

urlpatterns = [
    path('', user_views.HomeView.as_view(), name='menu'),
    path('newMicroContent/<int:preq>/<int:media>/<int:postq>', views.MicroContentCreationView.as_view(), name='microcontent_creation'), 
    path('microcontent_search/', views.MicroContentSearchView.as_view(), name='microcontent_search'),
    path('createSelection/', views.CreateSelectionView.as_view(), name='create_selection'),
    path('store/<int:pre_questions>/<int:post_questions>/', views.StoreView.as_view(), name='store'),
    path('delete/<int:id_metadata>/', views.DeleteView.as_view(), name='delete'),
    path('preview/<int:id_metadata>/', views.PreviewView.as_view(), name='preview'),
    path('edit_microcontent/<int:id_metadata>/', views.EditView.as_view(), name='edit_microcontent'),
    path('playlist_creation/', views.CreatePlaylistView.as_view(), name='playlist_creation'),
    path('playlist_search/', views.PlaylistSearchView.as_view(), name='playlist_search'),
    path('edit_playlist/<int:id_playlist>/', views.EditPlaylistView.as_view(), name='edit_playlist'),
    path('preview_playlist/<int:id_playlist>/', views.PreviewPlaylistView.as_view(), name='preview_playlist'),
    path('preview_keyword/<int:id_playlist>/<str:keyword>', views.PreviewKeywordView.as_view(), name='preview_keyword'),
    path('delete_playlist/<int:id_playlist>/', views.DeletePlaylistView.as_view(), name='delete_playlist'),
    path('duplicate_microcontent/<int:id_metadata>/<user>/', views.DuplicateMicrocontentView.as_view(), name='duplicate_microcontent'),
    path('duplicate_playlist/<int:id_playlist>/', views.DuplicatePlaylistView.as_view(), name='duplicate_playlist'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)