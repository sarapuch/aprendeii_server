from django.test import TestCase, Client
from django.urls import reverse
from .models import Media, MetaData, Question, MicroContent, Prequestionnaire, Postquestionnaire, SortedMicrocontent, Playlist
from django.utils import timezone


class TestViews(TestCase):

    def setUp(self):
        self.client = Client()


    def test_MicroContentSearchView_GET(self):
        response = self.client.get(reverse('authoringtool:microcontent_search', args=[0]))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/microcontent_list.html')


    def test_CreateSelectionView_GET(self):
        response = self.client.get(reverse('authoringtool:create_selection'))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/create_selection.html')    


    def test_MicroContentCreationView_GET(self):    
        response = self.client.get(reverse('authoringtool:microcontent_creation', args=[0, 0, 0]))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/create.html')


    def test_StoreView_POST(self):    
        response = self.client.get(reverse('authoringtool:store', args=[0, 0])) #Editar: ten que ser con POST
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/store.html')    


    def test_DeleteView_GET(self):    

        MicroContent.objects.create(
            name = 'some_name',
            level = 'know',
            metadata = MetaData.objects.create(
                id = 0,
                title = 'some_title',
                author = 'me',
                pub_date = timezone.now(),
                last_modification = timezone.now()
            ),
            media = None,
            pre_questionaire = None,
            post_questionaire = None
        )

        response = self.client.get(reverse('authoringtool:delete', args=[0]))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/delete.html')     


    def test_PreviewView_GET(self):    

        MicroContent.objects.create(
            name = 'some_name',
            level = 'know',
            metadata = MetaData.objects.create(
                id = 0,
                title = 'some_title',
                author = 'me',
                pub_date = timezone.now(),
                last_modification = timezone.now()
            ),
            media = None,
            pre_questionaire = Prequestionnaire.objects.create(),
            post_questionaire = Postquestionnaire.objects.create()
        )
        
        response = self.client.get(reverse('authoringtool:preview', args=[0]))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/preview.html')


    def test_EditView_GET(self):    

        MicroContent.objects.create(
            name = 'some_name',
            level = 'know',
            metadata = MetaData.objects.create(
                id = 0,
                title = 'some_title',
                author = 'me',
                pub_date = timezone.now(),
                last_modification = timezone.now()
            ),
            media = None,
            pre_questionaire = Prequestionnaire.objects.create(),
            post_questionaire = Postquestionnaire.objects.create()
        )
        
        response = self.client.get(reverse('authoringtool:edit_microcontent', args=[0]))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/edit_microcontent.html')      


    def test_CreatePlaylistView_GET(self):
        response = self.client.get(reverse('authoringtool:playlist_creation'))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'authoringtool/playlist_creation.html')   