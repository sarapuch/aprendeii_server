from django.test import TestCase, SimpleTestCase, Client
from django.urls import reverse, resolve
from .views import MicroContentCreationView, MicroContentSearchView, CreateSelectionView, StoreView, DeleteView, PreviewView, EditView, CreatePlaylistView, PlaylistSearchView, EditPlaylistView, PreviewPlaylistView, DeletePlaylistView


class TestsUrls(SimpleTestCase):

    
    def test_microcontent_creation_url_resolves(self):
        url = reverse('authoringtool:microcontent_creation', args=[0, 0, 0])
        self.assertEquals(resolve(url).func.view_class, MicroContentCreationView)
    
    """
    def test_microcontent_creation_url_resolves(self):
        
        c = Client()
        response = c.post('authoringtool:microcontent_creation', {'preq': 1, 'media': 1, 'postq': 1})
        print(response)
        self.assertEqual(response.status_code, 200)    
    """

    def test_microcontent_search_url_resolves(self):
        url = reverse('authoringtool:microcontent_search', args=[0])
        self.assertEquals(resolve(url).func.view_class, MicroContentSearchView)    

    
    def test_create_selection_url_resolves(self):
        url = reverse('authoringtool:create_selection')
        self.assertEquals(resolve(url).func.view_class, CreateSelectionView)


    def test_store_url_resolves(self):
        url = reverse('authoringtool:store', args=[0, 0])
        self.assertEquals(resolve(url).func.view_class, StoreView)     


    def test_delete_url_resolves(self):
        url = reverse('authoringtool:delete', args=[0])
        self.assertEquals(resolve(url).func.view_class, DeleteView)    


    def test_preview_url_resolves(self):
        url = reverse('authoringtool:preview', args=[0])
        self.assertEquals(resolve(url).func.view_class, PreviewView)     


    def test_edit_microcontent_url_resolves(self):
        url = reverse('authoringtool:edit_microcontent', args=[0])
        self.assertEquals(resolve(url).func.view_class, EditView)     


    def test_playlist_creation_url_resolves(self):       
        url = reverse('authoringtool:playlist_creation')
        self.assertEquals(resolve(url).func.view_class, CreatePlaylistView)   


    def test_playlist_search_url_resolves(self):  
        url = reverse('authoringtool:playlist_search')
        self.assertEquals(resolve(url).func.view_class, PlaylistSearchView)    


    def test_edit_playlist_url_resolves(self):
        url = reverse('authoringtool:edit_playlist', args=[0])
        self.assertEquals(resolve(url).func.view_class, EditPlaylistView)


    def test_preview_playlist_url_resolves(self):
        url = reverse('authoringtool:preview_playlist', args=[0])
        self.assertEquals(resolve(url).func.view_class, PreviewPlaylistView)


    def test_delete_playlist_url_resolves(self):
        url = reverse('authoringtool:delete_playlist', args=[0])
        self.assertEquals(resolve(url).func.view_class, DeletePlaylistView)              