from datetime import time
from typing import List
from .models import Media, MetaData, Question, MicroContent, Prequestionnaire, Postquestionnaire, SortedMicrocontent, Playlist, Keyword
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views import generic
from django.utils import timezone
from django.utils.datastructures import MultiValueDictKeyError
import sqlite3
import operator
from django.conf import settings

NUMBER_PARAGRAPHS = 1
NUMBER_CHOICES = 3
NUMBER_QUESTIONS = 1

#LISTADO DE MICROCONTENIDOS
class MicroContentSearchView(generic.DetailView):
    template_name = 'authoringtool/microcontent_list.html'

    def get(self, request, *args, **kwargs):

        microcontents = MicroContent.objects.filter(show='yes').order_by('-metadata_id')
        
        return render(request, 'authoringtool/microcontent_list.html', {"microcontents": microcontents})

#ELECCION DE TIPO DE MICROCONTENIDO
class CreateSelectionView(generic.TemplateView):

    def get(self, request, *args, **kwargs):
        return render(request, 'authoringtool/create_selection.html')

#CREACION DE MICROCONTENIDO
class MicroContentCreationView(generic.CreateView):
    success_url = reverse_lazy('auth_tool:index')
    template_name = 'authoringtool/create.html'

    def get(self, request, *args, **kwargs):
        return render(request, 'authoringtool/create.html', {'paragraphs': ' ' * NUMBER_PARAGRAPHS,
                                                             'preQuestionnaire': kwargs['preq'],
                                                             'media': kwargs['media'],
                                                             'postQuestionnaire': kwargs['postq'],
                                                             'numberQuestions': NUMBER_QUESTIONS,
                                                             'numberChoices': ' ' * NUMBER_CHOICES})

#GUARDAR MICROCONTENIDO
class StoreView(generic.TemplateView):
    template_name = 'authoringtool/store.html'

    def post(self, request, *args, **kwargs):
        # prequestionnaire
        prequestionnaire = Prequestionnaire()
        prequestionnaire.save()

        # for of number questions size
        for q in range(int(kwargs['pre_questions'])):
            q = q+1
            try:
                # statement of the question
                question_statement = request.POST['prequestion' + str(q)]
                first_choice = request.POST['prechoice' + str(q) + "_" + str(1)]
                second_choice = request.POST['prechoice' + str(q) + "_" + str(2)]
                third_choice = request.POST['prechoice' + str(q) + "_" + str(3)]
                correct_answer = request.POST[request.POST['preanswer' + str(q)]]
                explanation = request.POST['preexplanation' + str(q)]
                order = request.POST['preorder' + str(q)]

                question = Question(question=question_statement,
                                    first_choice=first_choice,
                                    second_choice=second_choice,
                                    third_choice=third_choice,
                                    correct_answer=correct_answer,
                                    explanation=explanation,
                                    order_in_questionnaire=order)
                question.save()
                prequestionnaire.question.add(question)
            except MultiValueDictKeyError:
                pass

        # postquestionnaire
        postquestionnaire = Postquestionnaire()
        postquestionnaire.save()

        # for of number questions size
        for q in range(int(kwargs['post_questions'])):
            q = q+1
            try:
                # statement of the question
                question_statement = request.POST['postquestion' + str(q)]
                first_choice = request.POST['postchoice' +
                                            str(q) + "_" + str(1)]
                second_choice = request.POST['postchoice' +
                                             str(q) + "_" + str(2)]
                third_choice = request.POST['postchoice' +
                                            str(q) + "_" + str(3)]
                correct_answer = request.POST[request.POST['postanswer' +
                                                           str(q)]]
                explanation = request.POST['postexplanation' + str(q)]
                order = request.POST['postorder' + str(q)]

                question = Question(question=question_statement,
                                    first_choice=first_choice,
                                    second_choice=second_choice,
                                    third_choice=third_choice,
                                    correct_answer=correct_answer,
                                    explanation=explanation,
                                    order_in_questionnaire=order)
                question.save()
                postquestionnaire.question.add(question)
            except MultiValueDictKeyError as err:
                print(err)
                pass

        name = request.POST['title']

        level = request.POST['level']

        unit = 'notused'

        description = request.POST['description']

        keywords = request.POST['keywords']

        metadata = MetaData(title=request.POST['title'], author=request.POST['author'], pub_date=timezone.now(), last_modification=timezone.now())
        metadata.save()

        if 'mediaType' in request.POST:
            if request.POST['mediaType'] == "video":
                if request.POST['upload_form'] == "from_existing_file":
                    media = Media(type=request.POST['mediaType'], 
                                url=Media.buildURL(request), 
                                upload_form=request.POST['upload_form'],
                                mediaFile=request.FILES['videoFile'],
                                text=request.POST['text'])
                else:
                    media = Media(type=request.POST['mediaType'], 
                                url=request.POST['videoURL'], 
                                upload_form=request.POST['upload_form'],
                                mediaFile=None,
                                text=request.POST['text'])
            
            if request.POST['mediaType'] == "audio":
                media = Media(type=request.POST['mediaType'], 
                                url=Media.buildURL(request), 
                                upload_form=request.POST['upload_form'],
                                mediaFile=request.FILES['audioFile'],
                                text=request.POST['text'])

            if request.POST['mediaType'] == "image":
                media = Media(type=request.POST['mediaType'], 
                                url=Media.buildURL(request), 
                                upload_form=request.POST['upload_form'],
                                mediaFile=request.FILES['imageFile'],
                                text=request.POST['text'])                    

            if request.POST['mediaType'] == "text":
                media = Media(type=request.POST['mediaType'], 
                                url=None,
                                upload_form=None,
                                mediaFile=None,
                                text=request.POST['text'])

            media.id_telegram = request.POST['id_telegram']
            media.save()

            content = MicroContent(name=name, level=level, playlist=unit, description=description, keywords=keywords, metadata=metadata, media=media,
                                   pre_questionaire=prequestionnaire, post_questionaire=postquestionnaire, show='yes')
        else:
            content = MicroContent(
                name=name, level=level, playlist=unit, description=description, keywords=keywords, metadata=metadata, pre_questionaire=prequestionnaire, post_questionaire=postquestionnaire, show='yes')
        content.save()

        mc = MicroContent.objects.filter(name=name, show='yes').get()
        mc_id = mc.metadata_id

        return render(request, 'authoringtool/store.html', {'mc_id': mc_id})

#DUPLICAR MICROCONTENIDO
class DuplicateMicrocontentView(generic.TemplateView):
    template_name = 'authoringtool/duplicate_microcontent.html'

    def get(self, request, *args, **kwargs):
        id_metadata = int(kwargs['id_metadata'])
        mc = MicroContent.objects.filter(metadata_id=id_metadata).get()

        name = mc.name + "- copy"

        keywords = mc.keywords
        description = mc.description

        user = kwargs['user']

        try:
            media = Media(type=mc.media.type, upload_form=mc.media.upload_form, url=mc.media.url, mediaFile=mc.media.mediaFile, text=mc.media.text, id_telegram=mc.media.id_telegram)
            media.save()
        except:
            pass
        

        metadata = MetaData(title=name, author=user, pub_date=timezone.now(), last_modification=timezone.now())
        metadata.save()

        #Prequestionnaire
        prequestionnaire = Prequestionnaire()
        prequestionnaire.save()

        pre_questions = mc.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        for preq in pre_questions:
            question = Question(question=preq.question, first_choice=preq.first_choice, second_choice=preq.second_choice, third_choice=preq.third_choice, correct_answer=preq.correct_answer, explanation=preq.explanation)
            question.save()
            prequestionnaire.question.add(question)

        #Postquestionnaire
        postquestionnaire = Postquestionnaire()
        postquestionnaire.save()

        post_questions = mc.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        for postq in post_questions:
            question = Question(question=postq.question, first_choice=postq.first_choice, second_choice=postq.second_choice, third_choice=postq.third_choice, correct_answer=postq.correct_answer, explanation=postq.explanation)
            question.save()
            postquestionnaire.question.add(question)

        try:
            content = MicroContent(name=name, keywords=keywords, description=description, level=mc.level, metadata=metadata, media=media,
                pre_questionaire=prequestionnaire, post_questionaire=postquestionnaire, show='yes')
        except:
            content = MicroContent(name=name, keywords=keywords, description=description, level=mc.level, metadata=metadata, pre_questionaire=prequestionnaire, post_questionaire=postquestionnaire, show='yes')
        
        content.save()

        mc = MicroContent.objects.filter(name=name, show='yes').get()
        mc_id = mc.metadata_id

        return render(request, 'authoringtool/duplicate_microcontent.html', {'id_metadata': id_metadata,'mc_id':mc_id})

#ELIMINACION DE MICROCONTENIDO DEL LISTADO
class DeleteView(generic.TemplateView):
    template_name = 'authoringtool/delete.html'

    def get(self, request, *args, **kwargs):
        id_metadata = int(kwargs['id_metadata'])
        mc = MicroContent.objects.filter(metadata_id=id_metadata).get()
        mc_name = mc.name
        mc.show = 'no'
        mc.save()

        return render(request, 'authoringtool/delete.html', {'id_metadata': id_metadata,
                                                             'name': mc_name})

#PREVISUALIZACION DE MICROCONTENIDO
class PreviewView(generic.TemplateView):
    template_name = 'authoringtool/preview.html'

    def get(self, request, *args, **kwargs):
        id_metadata = int(kwargs['id_metadata'])
        microcontent = MicroContent.objects.filter(metadata_id=id_metadata).get()

        try:
            pre_questions = microcontent.pre_questionaire.question.all()
            pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))
        except AttributeError:
            pre_questions = None

        try:
            media = microcontent.media
        except AttributeError:
            media = None 

        try:
            post_questions = microcontent.post_questionaire.question.all()
            post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))
        except AttributeError:
            post_questions = None

        return render(request, 'authoringtool/preview.html', {'microcontent': microcontent,
                                                              'pre_questions': pre_questions,
                                                              'media': media,
                                                              'post_questions': post_questions,
                                                              'dir': settings.MEDIA_DIRECTORIO})

#MODIFICACION DE MICROCONTENIDO
class EditView(generic.TemplateView):
    template_name = 'authoringtool/edit_microcontent.html'

    def get(self, request, *args, **kwargs):
        id_metadata = int(kwargs['id_metadata'])
        microcontent = MicroContent.objects.filter(metadata_id=id_metadata).get()
        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        try:
            media = microcontent.media
        except AttributeError:
            media = None 

        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))
        return render(request, 'authoringtool/edit_microcontent.html', {'microcontent': microcontent,
                                                                        'pre_questions': pre_questions,
                                                                        'media': media,
                                                                        'post_questions': post_questions,
                                                                        'numberChoices': ' ' * NUMBER_CHOICES,
                                                                        'dir': settings.MEDIA_DIRECTORIO,
                                                                        'keywords': microcontent.keywords})


    def post(self, request, *args, **kwargs):
        id_metadata = int(kwargs['id_metadata'])
        microcontent = MicroContent.objects.filter(metadata_id=id_metadata).get()

        #Now create a new microcontent
        prequestionnaire = Prequestionnaire()
        prequestionnaire.save()

        # for of number questions size
        for q in range(int(request.POST['idPreviousQuestions'])):
            q = q+1
            try:
                # statement of the question
                question_statement = request.POST['prequestion' + str(q)]
                first_choice = request.POST['prechoice' + str(q) + "_" + str(1)]
                second_choice = request.POST['prechoice' + str(q) + "_" + str(2)]
                third_choice = request.POST['prechoice' + str(q) + "_" + str(3)]
                correct_answer = request.POST[request.POST['preanswer' + str(q)]]
                explanation = request.POST['preexplanation' + str(q)]
                order = request.POST['preorder' + str(q)]

                question = Question(question=question_statement,
                                    first_choice=first_choice,
                                    second_choice=second_choice,
                                    third_choice=third_choice,
                                    correct_answer=correct_answer,
                                    explanation=explanation,
                                    order_in_questionnaire=order)
                question.save()
                prequestionnaire.question.add(question)
            except MultiValueDictKeyError:
                pass

        microcontent.pre_questionaire = prequestionnaire


        # postquestionnaire
        postquestionnaire = Postquestionnaire()
        postquestionnaire.save()

        # for of number questions size
        for q in range(int(request.POST['idPostQuestions'])):
            q = q+1
            try:
                # statement of the question
                question_statement = request.POST['postquestion' + str(q)]
                first_choice = request.POST['postchoice' +
                                            str(q) + "_" + str(1)]
                second_choice = request.POST['postchoice' +
                                             str(q) + "_" + str(2)]
                third_choice = request.POST['postchoice' +
                                            str(q) + "_" + str(3)]
                correct_answer = request.POST[request.POST['postanswer' +
                                                           str(q)]]
                explanation = request.POST['postexplanation' + str(q)]
                order = request.POST['postorder' + str(q)]

                question = Question(question=question_statement,
                                    first_choice=first_choice,
                                    second_choice=second_choice,
                                    third_choice=third_choice,
                                    correct_answer=correct_answer,
                                    explanation=explanation,
                                    order_in_questionnaire=order)
                question.save()
                postquestionnaire.question.add(question)
            except MultiValueDictKeyError as err:
                print(err)
                pass
        
        microcontent.post_questionaire = postquestionnaire

        name = request.POST['title']
        microcontent.name = name

        level = request.POST['level']
        microcontent.level = level
        
        keywords = request.POST['keywords']
        microcontent.keywords = keywords

        description = request.POST['description']
        microcontent.description = description

        microcontent.metadata.last_modification = timezone.now()
        
        if 'mediaType' in request.POST:
            if request.POST['mediaType'] == "video":
                if request.POST['upload_form'] == "from_existing_file":
                    try:
                        media = Media(type=request.POST['mediaType'], 
                                url=Media.buildURL(request), 
                                upload_form=request.POST['upload_form'],
                                mediaFile=request.FILES['videoFile'],
                                text=request.POST['text'])
                    except:
                        media = 'notmodified'
                else:
                    try:
                        media = Media(type=request.POST['mediaType'], 
                                url=request.POST['videoURL'], 
                                upload_form=request.POST['upload_form'],
                                mediaFile=None,
                                text=request.POST['text'])
                    except:
                        media = 'notmodified'
            
            if request.POST['mediaType'] == "audio":
                try:
                    media = Media(type=request.POST['mediaType'], 
                                url=Media.buildURL(request), 
                                upload_form=request.POST['upload_form'],
                                mediaFile=request.FILES['audioFile'],
                                text=request.POST['text'])
                except:
                        media = 'notmodified'

            if request.POST['mediaType'] == "image":
                try:
                    media = Media(type=request.POST['mediaType'], 
                                url=Media.buildURL(request), 
                                upload_form=request.POST['upload_form'],
                                mediaFile=request.FILES['imageFile'],
                                text=request.POST['text'])
                except:
                        media = 'notmodified'                  

            if request.POST['mediaType'] == "text":
                media = Media(type=request.POST['mediaType'], 
                                url=None,
                                upload_form=None,
                                mediaFile=None,
                                text=request.POST['text'])
            
            if media == 'notmodified':
                microcontent.media.id_telegram = request.POST['id_telegram']
            else:
                media.id_telegram = request.POST['id_telegram']
                media.save()
                microcontent.media = media

        microcontent.save()

        return render(request, 'authoringtool/store.html', {'mc_id': id_metadata})

#CREACION DE UNIDAD
class CreatePlaylistView(generic.TemplateView):

    def get(self, request, *args, **kwargs):
        microcontents = MicroContent.objects.filter(show='yes').all()
        keywords = []
        for mc in microcontents:
            if mc.keywords not in keywords:
                #cambio: se crea la unidad por keywords. generacion de lista
                keywords.append(mc.keywords)
        
        keywords.reverse()

        return render(request, 'authoringtool/playlist_creation.html', {"microcontents": keywords})


    def post(self, request, *args, **kwargs):

        name = request.POST['title']

        playlist = Playlist(name=name, show='yes')
        playlist.save()

        for order in range(int(request.POST['playlist_size']) - 1):
            order += 1

            try:
                #cambio: se guarda la lista ordenada por keywords
                mc_keyword = request.POST['order_' + str(order)]
                microcontent_selected = MicroContent.objects.filter(keywords = mc_keyword)
                try:
                    
                    for mc in microcontent_selected:
                        sorted_microcontent = SortedMicrocontent(order_in_playlist=str(order))
                        sorted_microcontent.save()
                        sorted_microcontent.microcontent.add(mc)
                        playlist.microcontent_list.add(sorted_microcontent)
                        order += 1

                except:
                    sorted_microcontent = SortedMicrocontent(order_in_playlist=str(order))
                    sorted_microcontent.save()
                    sorted_microcontent.microcontent.add(microcontent_selected)
                    playlist.microcontent_list.add(sorted_microcontent)

            except MultiValueDictKeyError as err:
                print(err)
                pass
        
        return render(request, 'authoringtool/store_playlist.html')

#VISUALIZACION DE LISTADO DE UNIDADES
class PlaylistSearchView(generic.DetailView):
    template_name = 'authoringtool/playlist_list.html'

    def get(self, request, *args, **kwargs):

        playlists = Playlist.objects.filter(show='yes')
        
        return render(request, 'authoringtool/playlist_list.html', {"playlists": playlists})

#MODIFICAR UNIDAD
class EditPlaylistView(generic.TemplateView):
    template_name = 'authoringtool/edit_playlist.html'

    def get(self, request, *args, **kwargs):

        id_playlist = int(kwargs['id_playlist'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist

        #lista de mcs en playlist
        aux_playlist = []
        for i in range(playlist.microcontent_list.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=playlist.microcontent_list.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]
            aux_playlist.append(mc_aux)

        #cambio: ahora se edita por keywords en vez de por microcontenidos
        keywords_in = []
        for mc in aux_playlist:
            if mc.keywords not in keywords_in:
                keywords_in.append(mc.keywords)

        microcontents = MicroContent.objects.filter(show='yes') #todos os mcs

        #lista auxiliar con todos os mcs para non ter problemas de typado ao facer a diferencia entre as listas
        aux_mcs_list = []
        for i in range(microcontents.count()):
            aux_mcs_list.append(microcontents[i])

        #lista dos mcs que non se encontran na playlist
        mcs_out_playlist = list(set(aux_mcs_list) - set(aux_playlist))
        keywords_out = []
        for mc in mcs_out_playlist:
            if mc.keywords not in keywords_out:
                keywords_out.append(mc.keywords)

        keywords_out.reverse()

        return render(request, 'authoringtool/edit_playlist.html', {"playlist": playlist,
                                                                    "microcontents_in": keywords_in,
                                                                    "microcontents_out": keywords_out})


    def post(self, request, *args, **kwargs):

        id_playlist = int(kwargs['id_playlist'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Edited playlist

        name = request.POST['title']
        playlist.name=name

        for sorted_mc in playlist.microcontent_list.all():
            sorted_mc.delete()

        for order in range(int(request.POST['playlist_size']) - 1):
            order += 1

            try:
                #cambio: creacion de playlist ordenada por keywords
                mc_keyword = request.POST['order_' + str(order)] 
                microcontent_selected = MicroContent.objects.filter(keywords=mc_keyword)
                try:
                    for mc in microcontent_selected:
                        sorted_microcontent = SortedMicrocontent(order_in_playlist=str(order))
                        sorted_microcontent.save()
                        sorted_microcontent.microcontent.add(mc)
                        playlist.microcontent_list.add(sorted_microcontent)
                        order += 1
                except:
                    sorted_microcontent = SortedMicrocontent(order_in_playlist=str(order))
                    sorted_microcontent.save()
                    sorted_microcontent.microcontent.add(microcontent_selected)
                    playlist.microcontent_list.add(sorted_microcontent)

            except MultiValueDictKeyError as err:
                print(err)
                pass 
            
        playlist.save()

        return render(request, 'authoringtool/store.html')

#DUPLICAR UNIDAD
class DuplicatePlaylistView(generic.TemplateView):
    template_name = 'authoringtool/duplicate_playlist.html'

    def get(self, request, *args, **kwargs):
        id_playlist = int(kwargs['id_playlist'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist

        name = playlist.name + "- copy"

        new_playlist = Playlist(name=name, show='yes')
        new_playlist.save()

        
        for sorted_mc in playlist.microcontent_list.all():
            sorted_microcontent=SortedMicrocontent(order_in_playlist=sorted_mc.order_in_playlist)
            sorted_microcontent.save()
            sorted_microcontent.microcontent.add(sorted_mc.microcontent.get())
            new_playlist.microcontent_list.add(sorted_microcontent)

        return render(request, 'authoringtool/duplicate_playlist.html', {'id_playlist': id_playlist})

#PREVISUALIZACION DE KEYWORDS POR UNIDAD
class PreviewPlaylistView(generic.TemplateView):
    template_name = 'authoringtool/preview_playlist.html'

    def get(self, request, *args, **kwargs):
        id_playlist = int(kwargs['id_playlist'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist

        #lista de mcs en playlist
        aux_playlist = []
        for i in range(playlist.microcontent_list.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=playlist.microcontent_list.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]
            aux_playlist.append(mc_aux)

        keyword = []
        for i in aux_playlist:
            if i.keywords not in keyword:
                keyword.append(i.keywords)
                
        return render(request, 'authoringtool/preview_playlist.html', {"playlist": playlist,
                                                                       "keywords_in": keyword})

#PREVISUALIZACION DE MICROCONTENIDOS POR KEYWORD
class PreviewKeywordView(generic.TemplateView):
    template_name = 'authoringtool/preview_playlist.html'

    def get(self, request, *args, **kwargs):
        id_playlist = int(kwargs['id_playlist'])
        keyword = str(kwargs['keyword'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist

        #lista de mcs en playlist
        aux_playlist = []
        for i in range(playlist.microcontent_list.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=playlist.microcontent_list.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]
            if mc_aux.keywords == keyword:
                aux_playlist.append(mc_aux)

        return render(request, 'authoringtool/preview_keyword.html', {"playlist": playlist,
                                                                       "microcontents_in": aux_playlist})

#ELIMINAR DEL LISTADO LA UNIDAD
class DeletePlaylistView(generic.TemplateView):
    template_name = 'authoringtool/delete_playlist.html'

    def get(self, request, *args, **kwargs):
        id_playlist = int(kwargs['id_playlist'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist
        name = playlist.name
        playlist.show = 'no'
        playlist.save()

        return render(request, 'authoringtool/delete_playlist.html', {"id_playlist": id_playlist,
                                                                       "name": name})