from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.forms.models import model_to_dict
import sqlite3

# Create your models here.

UPLOAD_FORM = (
    ('FROM_FILE', 'FROM EXISTING FILE'),
    ('LINK_FROM_YOUTUBE', 'LINK FROM YOUTUBE'),
    ('DOWNLOAD_FROM_YOUTUBE', 'DOWNLOAD FROM YOUTUBE'),
    ('EXTERNAL_REPOSITORY', 'EXTERNAL REPOSITORY'),
)

class ConfigValues(models.Model):
    typeI = models.IntegerField(default=3)
    typeII = models.IntegerField(default=1)
    typeIII = models.IntegerField(default=1)
    level_red_orange = models.IntegerField(default=8)
    level_orange_green = models.IntegerField(default=10)

class MetaData(models.Model):
    """
    Basic information about who and when created this content
    """
    title = models.CharField(max_length=200)
    author = models.CharField(max_length=200)
    pub_date = models.DateTimeField('Date published')
    last_modification = models.DateTimeField('Last modification')

    def __str__(self):
        return self.title


class Keyword(models.Model):
    name = models.CharField(max_length=50)


class Media(models.Model):
    """
    Represents the central element of a microcontent.
    It can be empty, a video, a picture, a text, a sound-recording, etc.
    It can be a link or an actual resource.
    """
    # TODO: O tipo debera ser un enumerado.
    type = models.CharField(max_length=50)
    upload_form = models.CharField(
        default='',
        max_length=50,
        null=True
    )
    url = models.CharField(
        max_length=1000,
        null=True
    )
    mediaFile = models.FileField(null=True)
    text = models.CharField(max_length=3000)
    id_telegram = models.CharField(
        max_length=10000,
        null=True
    )

    def __str__(self):
        return self.url + ": " + str(self.mediaFile)

    def toDict(self):
        return model_to_dict(self, fields=['type', 'url', 'upload_form', 'text'])

    @staticmethod
    def buildURL(request):

        videoURL = ""
        if request.POST['mediaType'] == "video":
            videoURL = request.POST['videoURL']
            if request.POST['upload_form'] == "link_from_youtube":
                idYoutubeVideo = videoURL.split("v=", 1)[1]
                videoURL = "http://www.youtube.com/embed/" + idYoutubeVideo

            if request.POST['upload_form'] == "from_existing_file":
                video_file = request.FILES['videoFile']
                # Get the name of the file to access to it when the micro-content is requested from external tool
                videoURL = video_file.name
            return videoURL

        if request.POST['mediaType'] == "audio":
            audio_file = request.FILES['audioFile']
            # Get the name of the file to access to it when the micro-content is requested from external tool
            audioURL = audio_file.name
            return audioURL

        if request.POST['mediaType'] == "image":
            image_file = request.FILES['imageFile']
            # Get the name of the file to access to it when the micro-content is requested from external tool
            imageURL = image_file.name
            return imageURL


class Question(models.Model):
    """
    Represents a multiple-choice question with just a right anwser
    """
    question = models.CharField(default='', max_length=300)
    first_choice = models.CharField(default='', max_length=300)
    second_choice = models.CharField(default='', max_length=300)
    third_choice = models.CharField(default='', max_length=300)
    correct_answer = models.CharField(default='', max_length=300)
    explanation = models.TextField(default='')
    order_in_questionnaire = models.CharField(default='', max_length=300)

    def __str__(self):
        return self.question

    def getcorrectoption(self):
        if self.correct_answer == self.first_choice:
            correct_option = 1
        elif self.correct_answer == self.second_choice:
            correct_option = 2
        elif self.correct_answer == self.third_choice:
            correct_option = 3
        
        return correct_option


class Prequestionnaire(models.Model):
    """
    Pre-media quiz
    """
    question = models.ManyToManyField(Question)


class Postquestionnaire(models.Model):
    """
    Post-media quiz
    """
    question = models.ManyToManyField(Question)


class MicroContent(models.Model):
    """
    Basic content unit, involving a media and several questions
    """
    name = models.CharField(max_length=200)

    level = models.CharField(max_length=200, null=True)

    playlist = models.CharField(max_length=200, null=True)

    description = models.CharField(max_length=200, null=True)
    
    keywords = models.CharField(max_length=50, default='needtochange')
    
    metadata = models.OneToOneField(
        MetaData,
        on_delete=models.CASCADE,
        primary_key=True,
    )

    media = models.OneToOneField(
        Media,
        on_delete=models.CASCADE,
        null=True
    )

    pre_questionaire = models.OneToOneField(
        Prequestionnaire,
        on_delete=models.CASCADE,
        null=True
    )

    post_questionaire = models.OneToOneField(
        Postquestionnaire,
        on_delete=models.CASCADE,
        null=True
    )

    show = models.CharField(max_length=10, null=True)

    def __str__(self):
        return self.name


class SortedMicrocontent(models.Model):
    """
    The basic unit in a playlist, involving a microcontent and its position on the playlist
    """
    microcontent = models.ManyToManyField(MicroContent)

    order_in_playlist = models.CharField(default='', max_length=200)


class Playlist(models.Model):
    """
    Micro content playlist
    """
    name = models.CharField(default='', max_length=200)
    
    microcontent_list = models.ManyToManyField(SortedMicrocontent)

    show = models.CharField(max_length=10, null=True)

    #configValues = models.OneToOneField(ConfigValues)
