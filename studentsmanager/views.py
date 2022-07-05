from ast import keyword
from django.contrib import messages
from django.contrib.auth.forms import PasswordResetForm, AuthenticationForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin, SuccessURLAllowedHostsMixin, \
    INTERNAL_RESET_SESSION_TOKEN, LoginView
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from django.http.response import Http404
from django.shortcuts import redirect, resolve_url
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    logout as auth_logout, update_session_auth_hash,
    authenticate)
from django.utils.datastructures import MultiValueDictKeyError
from importlib_metadata import metadata
from rest_framework import viewsets
from datetime import date, timedelta


from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
#añadida tras error en signup
from django.core.mail import send_mail
from django.core import serializers
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import generic
from django.utils import timezone
from django.forms.models import model_to_dict
from datetime import datetime
from dateutil.relativedelta import relativedelta
from studentsmanager.forms import UserCreateForm
from studentsmanager.serializers import UserSerializer
from studentsmanager.models import Keywords_State, Student, Trace, State, Comments

from authoringtool.models import Playlist, SortedMicrocontent, MicroContent

import json
import operator, random, requests

UserModel = get_user_model()

# API classes
class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
#

#VISUALIZACION DE PANTALLA DE INICIO
class HomeView(TemplateView):

    def get(self, request, *args, **kwargs):
        return render(request, 'studentsmanager/user_page.html')

#COMPROBACION DE DATOS --> AL EDITAR SE ENVIA A EditUserDataView
class UserDataView(TemplateView):
    def get(self, request, *args, **kwargs):
        student = Student.objects.filter(id=self.request.user.id).get()
        template_name = 'studentsmanager/user_data_show_and_edit.html'
        return render(request, template_name, {'students':student})

#PANTALLA DE REGISTRO/LOGIN
class LoginView(SuccessURLAllowedHostsMixin, FormView):
    """
        Display the login form and handle the login action.
        """
    form_class = AuthenticationForm
    authentication_form = None
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'registration/login.html'
    redirect_authenticated_user = False
    extra_context = None
    
    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if self.redirect_authenticated_user and self.request.user.is_authenticated:
            redirect_to = self.get_success_url()
            if redirect_to == self.request.path:
                raise ValueError(
                    "Redirection loop for authenticated user detected. Check that "
                    "your LOGIN_REDIRECT_URL doesn't point to a login page."
                )
            return HttpResponseRedirect(redirect_to)
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get_redirect_url(self):
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, '')
        )
        url_is_safe = url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else ''

    def get_form_class(self):
        return self.authentication_form or self.form_class

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def form_valid(self, form):
        """Security check complete. Log the user in."""
        auth_login(self.request, form.get_user())
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        current_site = get_current_site(self.request)
        context.update({
            self.redirect_field_name: self.get_redirect_url(),
            'site': current_site,
            'site_name': current_site.name,
            **(self.extra_context or {})
        })
        return context

#MODIFICACION DE CONTRASEÑAS
class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = 'registration/password_reset_email.html'
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')
    template_name = 'registration/password_reset_form.html'
    title = ('Password reset')
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': self.token_generator,
            'from_email': self.from_email,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'html_email_template_name': self.html_email_template_name,
            'extra_email_context': self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = True
    post_reset_login_backend = None
    success_url = reverse_lazy('password_reset_complete')
    template_name = 'registration/password_reset_confirm.html'
    title = ('Enter new password')
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        assert 'uidb64' in kwargs and 'token' in kwargs

        self.validlink = False
        self.user = self.get_user(kwargs['uidb64'])

        if self.user is not None:
            token = kwargs['token']
            if token == 'set-password': #INTERNAL_RESET_URL_TOKEN:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(token, 'set-password')
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64) #.decode()
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        if form.is_valid():
            username = self.user
            password = form.cleaned_data['new_password1']
            u = User.objects.get(username=username)
            u.set_password(password)
            u.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context['validlink'] = True
        else:
            context.update({
                'form': None,
                'title': 'Password reset unsuccessful',
                'validlink': False,
            })
        return context


def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('login')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'studentsmanager/password_change.html', {
        'form': form
    })


# The following are the accounts views #
#REGISTRO DE USUARIO: actualmente no funciona por exigencias de seguridad de google. no tenemos acceso al envio de correos por gmail.
class SignUp(generic.CreateView):
    form_class = UserCreateForm
    success_url = reverse_lazy('login')
    template_name = 'registration/login.html'

    def form_valid(self, form):
        user = form.save()
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            current_site = get_current_site(self.request)
            mail_subject = 'Activate the new user account.'
            message = render_to_string('studentsmanager/acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            email = EmailMessage(
                mail_subject, message, to=[settings.EMAIL_ADMIN_RECEIVER]  # admin email
            )
            email.send()
            return render(self.request, 'studentsmanager/confirm_registration.html')

        else:
            form = UserCreateForm()
        return render(self.request, 'registration/login.html', {'form': form})

#ACTIVACION DE USUARIO --> MISMO PROBLEMA ANTERIOR
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):  # Check if the token is correct
        user.is_active = True
        user.save()
        login(request, user)
        current_site = get_current_site(request)
        mail_subject = 'Account in MicroLearning Platform already activated'
        message = render_to_string('studentsmanager/user_link_confirmation.html', {
            'user': user,
            'domain': current_site.domain,
        })
        email = EmailMessage(
            mail_subject, message, to=[user.email]  # new user email
        )
        email.send()

        return HttpResponse('The selected account has been activated.')
    else:
        return HttpResponse('Activation link is invalid!')

#CREACION DE USUARIO. SOLUCION TEMPORAL
'''opcion alternativa a envios por correo, activación de cuenta de manera inmediata'''
class SignUpActive(generic.CreateView):
    form_class = UserCreateForm
    success_url = reverse_lazy('login')
    template_name = 'registration/login.html'

    def form_valid(self, form):
        user = form.save()
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.save()

            return render(self.request, 'studentsmanager/confirm_registration.html')

        else:
            form = UserCreateForm()
        return render(self.request, 'registration/login.html', {'form': form})

#MODIFICACION DE DATOS DE USUARIO
class EditUserDataView(generic.TemplateView):
    template_name = "studentsmanager/user_data_show_and_edit.html"

    def get(self, request, *args, **kwargs):
        student = Student.objects.filter(id=self.request.user.id).get()
        return render(request, "studentsmanager/user_data_show_and_edit.html", {'students': student})

    def post(self, request, *args, **kwargs):

        try:
            uid = kwargs['id']
            user = UserModel._default_manager.get(pk=uid)
            student = Student.objects.filter(id=self.request.user.id).get()
            user.username=request.POST['userName']
            user.first_name = request.POST['firstName']
            user.last_name = request.POST['lastName']
            user.email = request.POST['email']
            student.telegram_id = request.POST['telegram_id']
            user.save()
            student.save()

        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        
        return render(request, "studentsmanager/user_data_show_and_edit.html", {'students': student})

#LISTADO DE CURSOS
class CoursesListView(generic.TemplateView):

    template_name = "studentsmanager/courses_list.html"  

    def get(self, request, *args, **kwargs):
        student = Student.objects.filter(id=self.request.user.id).get()
        playlists = Playlist.objects.filter(show='yes')
        return render(request, 'studentsmanager/courses_list.html', {"playlists": playlists, "student":student.username})

#MATRICULARSE EN EL CURSO. USO PREVIO, NO HAY POSIBILIDAD DE ELECCION
class EnrollView(generic.TemplateView):

    template_name = "studentsmanager/enrolled.html"

    def get(self, request, *args, **kwargs):
        
        course_id = int(kwargs['course_id'])
        course = Playlist.objects.filter(id=course_id).get()

        student = Student.objects.filter(id=self.request.user.id).get()
        student.courses.add(course)
        states = student.states.all()

        for i in range(course.microcontent_list.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=course.microcontent_list.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]

            if not states.filter(microcontent = mc.metadata_id).all():
                state = State(semaphore="red", last_update=timezone.now())
                state.save()
                state.microcontent.add(mc)
                student.states.add(state)

                trace = Trace(microcontent=mc.name, action="Enrolls in a course with that microcontent", time=timezone.now())
                trace.save()

                student.tracking.add(trace)
        
        student.notification = True
        student.save()            

        return render(request, 'studentsmanager/enrolled.html')

#ELECCION DE ITINERARIO DENTRO DEL CURSO. SISTEMA DE MATRICULA ACTUAL
class ChooseItineraryView(generic.TemplateView):

    def get(self, request, *args, **kwargs):
        id_playlist = int(kwargs['course_id'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist

        student = Student.objects.filter(id=self.request.user.id).get()
        student.courses.add(playlist)
        states = student.states.all()

        keywords_in = []
        keywords_out = []
        aux_itinerary = []
        aux_playlist = []
        #SEPARACION DE KEYWORDS (POR SI YA ESTABA MATRICULADO). No funciona a la hora de marcar las checkboxes dentro de la plantilla
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
            aux_itinerary.append(mc)
            if mc.keywords not in keywords_in:
                keywords_in.append(mc.keywords)

        for i in range(playlist.microcontent_list.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=playlist.microcontent_list.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
            aux_playlist.append(mc)

        for mc in aux_playlist:
            if mc.keywords not in keywords_out:
                keywords_out.append(mc.keywords)
        

        return render(request, 'studentsmanager/itinerary_creation.html', {"playlist": playlist,
                                                                    "microcontents": keywords_out,
                                                                    "microcontents_in": keywords_in})

    def post(self, request, *args, **kwargs):

        id_playlist = int(kwargs['course_id'])
        playlist = Playlist.objects.filter(id=id_playlist).get() #Selected playlist
        student = Student.objects.filter(id=self.request.user.id).get()
        student.courses.add(playlist)
        states = student.states.all()

        for sorted in student.itinerary.all():
            sorted.delete()

        itinerary = request.POST.getlist('itinerary')
        keywords_state = student.keywords_states.all()
        order = 0
        try:
            
            for kw in itinerary:
                if not keywords_state.filter(keyword=kw).exists():
                    keyword_state = Keywords_State(keyword = kw)
                    keyword_state.save()
                    student.keywords_states.add(keyword_state)
                microcontent_selected = MicroContent.objects.filter(keywords = kw)
                try:
                    
                    for mc in microcontent_selected:
                        sorted_microcontent = SortedMicrocontent(order_in_playlist=str(order))
                        sorted_microcontent.save()
                        sorted_microcontent.microcontent.add(mc)
                        student.itinerary.add(sorted_microcontent)
                        order += 1

                except:
                    sorted_microcontent = SortedMicrocontent(order_in_playlist=str(order))
                    sorted_microcontent.save()
                    sorted_microcontent.microcontent.add(microcontent_selected)
                    student.itinerary.add(sorted_microcontent)
            student.save()
        except MultiValueDictKeyError as err:
            print(err)
            pass
        
        #generacion de trazas
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]

            if not states.filter(microcontent = mc.metadata_id).all():
                state = State(semaphore="red", last_update=timezone.now())
                state.save()
                state.microcontent.add(mc)
                student.states.add(state)

                trace = Trace(microcontent=mc.name, action="Enrolls in a course with that microcontent", time=timezone.now())
                trace.save()

                student.tracking.add(trace)

        student.notification = True
        student.save() 
        
        return render(request, 'studentsmanager/enrolled.html')

#LISTADO DE CURSOS MATRICULADOS
class MyCoursesView(generic.TemplateView):

    template_name = "studentsmanager/my_courses.html"

    def get(self, request, *args, **kwargs):

        student = Student.objects.filter(id=self.request.user.id).get()
        courses = student.courses.all()
        return render(request, 'studentsmanager/my_courses.html', {"courses": courses})

#REINICIO DE CURSO. **comprobar
class restartCourse(generic.TemplateView):
    
    def get(self,request,*args,**kwargs):

        course_id = int(kwargs['course_id'])

        student = Student.objects.filter(id=self.request.user.id).get()
        course = Playlist.objects.filter(id=course_id).get()
        states = student.states.all()
        
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]

            state_aux = states.filter(microcontent = mc.metadata_id).all()[0]
            state_aux.semaphore = 'red'
            state_aux.last_update = timezone.now()
            state_aux.save()

            trace = Trace(microcontent=mc.name, action="Restarted the course", time=timezone.now())
            trace.save()

            student.tracking.add(trace)
            student.current_keyword = 'start'
            student.save()
            try:
                keyword_state = student.keywords_states.filter(keyword = mc.keywords).get()
                keyword_state.score = 0
                keyword_state.semaphore = 'red'
                keyword_state.typeIIx3 = 0
                keyword_state.typeIIx2 = 0
                keyword_state.alreadydoneII = ''
                keyword_state.alreadydoneIII = ''
                keyword_state.save()
            except:
                pass

        
        return render(request, 'studentsmanager/restart_course.html')  

#PREVISUALIZACION DE KEYWORDS POR UNIDAD
class CourseKeywordView(generic.TemplateView):

    template_name = "studentsmanager/course_microcontents.html"

    def get(self, request, *args, **kwargs):   
        
        student = Student.objects.filter(id=self.request.user.id).get()

        course_id = int(kwargs['course_id'])
        course = Playlist.objects.filter(id = course_id).get()

        states = student.states.all()

        microcontents = []
        states_list = [] 
        
        student.courses.add(course)
        
        #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
            if not states.filter(microcontent = mc.metadata_id).all():
                state = State(semaphore="red", last_update=timezone.now())
                state.save()
                state.microcontent.add(mc)
                student.states.add(state)

                trace = Trace(microcontent=mc.name, action="Course updated", time=timezone.now())
                trace.save()

                student.tracking.add(trace)
        
        #conseguimos los microcontenidos para el usuario
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]    
            microcontents.append(mc_aux)

        keyword = []

        #clasificamos por keywords
        for i in microcontents:
            if i.keywords not in keyword:
                keyword.append(i.keywords)
        data = keyword
           

        return render(request, 'studentsmanager/course_keyword.html', {"data": data, "course_id": course_id}) 

#VISUALIZACION DE MICROCONTENIDOS POR KEYWORD
class CourseMicrocontentsView(generic.TemplateView):

    template_name = "studentsmanager/course_microcontents.html"

    def get(self, request, *args, **kwargs):   
        
        student = Student.objects.filter(id=self.request.user.id).get()

        course_id = int(kwargs['course_id'])
        course = Playlist.objects.filter(id = course_id).get()
        keyword = str(kwargs['keyword'])

        states = student.states.all()

        microcontents = []
        states_list = [] 
        
        student.courses.add(course)
        
        #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
            if not states.filter(microcontent = mc.metadata_id).all():
                state = State(semaphore="red", last_update=timezone.now())
                state.save()
                state.microcontent.add(mc)
                student.states.add(state)

                trace = Trace(microcontent=mc.name,action="Course updated", time=timezone.now())
                trace.save()

                student.tracking.add(trace)

        
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]    
            if mc_aux.keywords == keyword:
                microcontents.append(mc_aux)

        #recogemos los estados asociados al microcontenido  
        selection = []
        for m in microcontents:
            state_aux = states.filter(microcontent = m.metadata_id).all()[0]
            
            selection.append(m)
            states_list.append(state_aux)
                      
          
        data = zip(selection, states_list)
           

        return render(request, 'studentsmanager/course_microcontents.html', {"data": data}) 

#REALIZACION DE UNIDAD UTILIZANDO EL SECUENCIADOR. **comprobar si funciona
class TryPlaylistView(generic.TemplateView):
    def get(self, request, *args, **kwargs): 

        student = Student.objects.filter(id=self.request.user.id).get()

        course_id = int(kwargs['course_id'])
        course = Playlist.objects.filter(id = course_id).get()
        
        states = student.states.all()
        keyword_states = student.keywords_states.all()


        microcontents = []
        states_list = [] 
        microcontent = 'empty'
        student.courses.add(course)
        
        #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
            if not states.filter(microcontent = mc.metadata_id).all():
                state = State(semaphore="red", last_update=timezone.now())
                state.save()
                state.microcontent.add(mc)
                student.states.add(state)

                trace = Trace(microcontent=mc.name,action="Course updated", time=timezone.now())
                trace.save()

                student.tracking.add(trace)
        
        keywords = []
        
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]
            microcontents.append(mc_aux)
            if mc_aux.keywords not in keywords:
                keywords.append(mc_aux.keywords)

        if student.current_keyword =='start':
            student.current_keyword = keywords[0]
        else:
            pass
        student.save()
        keyword_state = keyword_states.filter(keyword=student.current_keyword).get()

        #copiar de funcion de telegram
        if (keyword_state.score == 3 and keyword_state.typeIIx3 == 3) or keyword_state.score == 0:
            keyword_state.typeIIx3 = 0
            keyword_state.score = 0
            keyword_state.save()
            microcontent = MicroContent.objects.filter(keywords=student.current_keyword, level='I').get()
        elif keyword_state.score >= 3 and keyword_state.typeIIx3 != 3:
            items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='II').all())
            microcontent = random.choice(items)
            try:
                alreadydone = keyword_state.alreadydoneII.split('-')
                while microcontent.metadata_id in alreadydone:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
                keyword_state.save()
            except:
                while microcontent.metadata_id == keyword_state.alreadydoneII:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
                keyword_state.save()
        elif keyword_state.score >= 6 and (keyword_state.typeIIx3 == 3 or keyword_state.typeIIx2 == 2):
            found = False
            while not found:
                for index, elem in enumerate(keywords):
                    if student.current_keyword == keywords[index]:
                        try:
                            student.current_keyword = keywords[index+1]
                            microcontent = MicroContent.objects.filter(keywords=student.current_keyword, level='I').get()
                            found = True
                        except:
                            found = True
        elif keyword_state.score == 4 and keyword_state.typeIIx3 == 3:
            items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='III').all())
            microcontent = random.choice(items)
            try:
                alreadydone = keyword_state.alreadydoneIII.split('-')
                while microcontent.metadata_id in alreadydone:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneIII += f"{microcontent.metadata_id}-"
                keyword_state.save()
            except:
                while microcontent.metadata_id == keyword_state.alreadydoneIII:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneIII += f"{microcontent.metadata_id}-"
        elif keyword_state.score >= 5 and keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 != 2:
            items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='II').all())
            microcontent = random.choice(items)
            try:
                alreadydone = keyword_state.alreadydoneII.split('-')
                while microcontent.metadata_id in alreadydone:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
                keyword_state.save()
            except:
                while microcontent.metadata_id == keyword_state.alreadydoneII:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
                keyword_state.save()
        elif keyword_state.score < 6 and keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 == 2:
            keyword_state.typeIIx2 = 0
            keyword_state.save()
            items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='II').all())
            microcontent = random.choice(items)
            try:
                alreadydone = keyword_state.alreadydoneII.split('-')
                while microcontent.metadata_id in alreadydone:
                   microcontent = random.choice(items)
                keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
                keyword_state.save()
            except:
                while microcontent.metadata_id == keyword_state.alreadydoneII:
                   microcontent = random.choice(items)
                keyword_state.alreadydone += f"{microcontent.metadata_id}-"
                keyword_state.save()

        if microcontent == 'empty':
            return render(request, 'studentsmanager/end_course.html')
        #microcontent = MicroContent.objects.filter(metadata_id = mc_id).get()

        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        try:
            media = microcontent.media
        except AttributeError:
            media = None 

        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        trace = Trace(microcontent=microcontent.name, action="Preview the microcontent", time=timezone.now())
        trace.save()

        student.tracking.add(trace)


        return render(request, 'studentsmanager/try_playlist.html', {"course_id": course_id,
                                                                        "microcontent" : microcontent,
                                                                        "pre_questions" : pre_questions,
                                                                        "media" : media,
                                                                        "post_questions" : post_questions,
                                                                        'dir': settings.MEDIA_DIRECTORIO})

    def post(self, request, *args, **kwargs):                                                                     
        student = Student.objects.filter(id=self.request.user.id).get()

        course_id = int(kwargs['course_id'])
        course = Playlist.objects.filter(id = course_id).get()

        micro_id = request.POST['metadata_id']
        
        states = student.states.all()
        keywords_state = student.keywords_states.all()

        microcontents = []
        states_list = [] 
        
        student.courses.add(course)
        
        #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
            if not states.filter(microcontent = mc.metadata_id).all():
                state = State(semaphore="red", last_update=timezone.now())
                state.save()
                state.microcontent.add(mc)
                student.states.add(state)

                trace = Trace(microcontent=mc.name,action="Course updated", time=timezone.now())
                trace.save()

                student.tracking.add(trace)

        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            microcontent = MicroContent.objects.filter(metadata_id = micro_id).get()
            mc = sorted_mc.microcontent.all()[0]
            if mc.name == microcontent.name:
                microcontent = mc
        
        state_aux = states.filter(microcontent = mc.metadata_id).all()[0]
        keyword_state = keywords_state.filter(keyword=microcontent.keywords).get()
        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        pre_questionnaire_list = []
        for i in range(len(pre_questions)):
            pre_questionnaire_score={}

            pre_questionnaire_score['question'] = pre_questions[i].question

            choice = request.POST['prechoice_' + str(i+1)]
            pre_questionnaire_score['choice'] = choice

            correct_answer = pre_questions[i].correct_answer
            pre_questionnaire_score['correct_answer'] = correct_answer #deberia mostrala?

            pre_questionnaire_score['explanation'] = pre_questions[i].correct_answer

            if(choice == correct_answer):
                pre_questionnaire_score['score'] = 'correct'
            else:
                pre_questionnaire_score['score'] = 'incorrect' 

            pre_questionnaire_list.append(pre_questionnaire_score)   

        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        post_questionnaire_list = []
        score = 0
        for i in range(len(post_questions)):
            post_questionnaire_score={}
            
            post_questionnaire_score['question'] = post_questions[i].question

            choice = request.POST['postchoice_' + str(i+1)]
            post_questionnaire_score['choice'] = choice

            correct_answer = post_questions[i].correct_answer
            post_questionnaire_score['correct_answer'] = correct_answer

            post_questionnaire_score['explanation'] = post_questions[i].correct_answer

            if(choice == correct_answer):
                post_questionnaire_score['score'] = 'correct'
                score +=1
            else:
                post_questionnaire_score['score'] = 'incorrect'
                
            post_questionnaire_list.append(post_questionnaire_score)

        if score == len(post_questions):
            if microcontent.level == 'I':
                keyword_state.score += 3
            elif microcontent.level == 'II':
                keyword_state.score += 1
            else:
                keyword_state.score += 1
            keyword_state.save()
            state = 'green'
        elif score >= (len(post_questions)/2):   #preguntar valores duda
            state = 'yellow'
        else:
            state = 'red' 

        if microcontent.level == 'II' and keyword_state.typeIIx3 != 3:
            keyword_state.typeIIx3 += 1
        else:
            keyword_state.typeIIx2 += 1
        keyword_state.save()

        state_aux.semaphore = state
        state_aux.last_update = timezone.now()
        state_aux.save()

        pre_questionnaire_text = ''.join([str(item) for item in pre_questionnaire_list])
        post_questionnaire_text = ''.join([str(item) for item in post_questionnaire_list])

        action = 'Solves microcontent. Q&A: ' + pre_questionnaire_text + post_questionnaire_text

        trace = Trace(microcontent = microcontent.name,action=action, time=timezone.now())
        trace.save()

        student.tracking.add(trace)
        student.save()

        return render(request, 'studentsmanager/score_playlist.html', {"course_id": course_id,
                                                            "pre_questionnaire_list" : pre_questionnaire_list,
                                                            "post_questionnaire_list" : post_questionnaire_list,
                                                            "state" : state})

#REALIZAR MICROCONTENIDO. NO SE MODIFICAN DATOS DE ESTADOS
class TryMicrocontentView(generic.TemplateView):

    template_name = "studentsmanager/try_microcontent.html"

    def get(self, request, *args, **kwargs): 

        student = Student.objects.filter(id=self.request.user.id).get()

        mc_id = int(kwargs['mc_id'])
        microcontent = MicroContent.objects.filter(metadata_id = mc_id).get()

        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        try:
            media = microcontent.media
        except AttributeError:
            media = None 

        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        trace = Trace(microcontent=microcontent.name,action="Preview the microcontent", time=timezone.now())
        trace.save()

        student.tracking.add(trace)


        return render(request, 'studentsmanager/try_microcontent.html', {"microcontent" : microcontent,
                                                                         "pre_questions" : pre_questions,
                                                                         "media" : media,
                                                                         "post_questions" : post_questions,
                                                                         'dir': settings.MEDIA_DIRECTORIO})

    def post(self, request, *args, **kwargs):                                                                     

        mc_id = int(kwargs['mc_id'])
        microcontent = MicroContent.objects.filter(metadata_id = mc_id).get()
        student = Student.objects.filter(id=self.request.user.id).get()
        states = student.states.all()
        state_aux = states.filter(microcontent = mc_id).all()[0]

        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        pre_questionnaire_list = []
        for i in range(len(pre_questions)):
            pre_questionnaire_score={}

            pre_questionnaire_score['question'] = pre_questions[i].question

            choice = request.POST['prechoice_' + str(i+1)]
            pre_questionnaire_score['choice'] = choice

            correct_answer = pre_questions[i].correct_answer
            pre_questionnaire_score['correct_answer'] = correct_answer #deberia mostrala?

            pre_questionnaire_score['explanation'] = pre_questions[i].correct_answer

            if(choice == correct_answer):
                pre_questionnaire_score['score'] = 'correct'
            else:
                pre_questionnaire_score['score'] = 'incorrect' 

            pre_questionnaire_list.append(pre_questionnaire_score)   



        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        post_questionnaire_list = []
        score = 0
        for i in range(len(post_questions)):
            post_questionnaire_score={}
            
            post_questionnaire_score['question'] = post_questions[i].question

            choice = request.POST['postchoice_' + str(i+1)]
            post_questionnaire_score['choice'] = choice

            correct_answer = post_questions[i].correct_answer
            post_questionnaire_score['correct_answer'] = correct_answer

            post_questionnaire_score['explanation'] = post_questions[i].correct_answer

            if(choice == correct_answer):
                post_questionnaire_score['score'] = 'correct'
                score +=1
            else:
                post_questionnaire_score['score'] = 'incorrect'
                
            post_questionnaire_list.append(post_questionnaire_score)

        if score == len(post_questions):
            state = 'green'
        elif score >= (len(post_questions)/2):   #preguntar valores duda
            state = 'yellow'
        else:
            state = 'red' 

        state_aux.semaphore = state
        state_aux.last_update = timezone.now()
        state_aux.save()

        pre_questionnaire_text = ''.join([str(item) for item in pre_questionnaire_list])
        post_questionnaire_text = ''.join([str(item) for item in post_questionnaire_list])

        action = 'Solves microcontent. Q&A: ' + pre_questionnaire_text + post_questionnaire_text

        trace = Trace(microcontent=microcontent.name,action=action, time=timezone.now())
        trace.save()

        student.tracking.add(trace)

        return render(request, 'studentsmanager/score.html', {"pre_questionnaire_list" : pre_questionnaire_list,
                                                              "post_questionnaire_list" : post_questionnaire_list,
                                                              "state" : state})


'''
FUNCIONES DE ALEXA. NECESARIO ACTUALIZAR FRENTE A LOS CAMBIOS ACTUALES
'''

#OBTENER DATOS DEL CURSO
def get_state_record(request, **kwargs):

    user = kwargs['user']
    course = kwargs['course']

    student = Student.objects.filter(username=user).get()
    playlist = Playlist.objects.filter(id=course).get()
    states = student.states.all()

    data={}
    for i in range(playlist.microcontent_list.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=playlist.microcontent_list.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0] #mcs neste curso/playlist
        state = states.filter(microcontent = mc.metadata_id).all()[0]
        data['microcontent_' + str(i)] = mc.metadata_id
        data['name_' + str(i)] = mc.name
        data['semaphore_' + str(i)] = state.semaphore
        data['date_' + str(i)] = str(state.last_update)

    data_json = json.dumps(data)

    return HttpResponse(data_json)

#OBTENER DATOS DE MICROCONTENIDO
def get_microcontent_state(user, microcontent):

    student = Student.objects.filter(id=user).get()
    state = student.states.filter(microcontent = microcontent).get()

    data={'semaphore' : state.semaphore, 'date' : str(state.last_update)}
    data_json = json.dumps(data)

    return data_json

#OBTENER CURSOS
def get_courses(request, **kwargs):

    user = kwargs['user']

    student = Student.objects.filter(username=user).get()
    courses = student.courses.all()

    data={}
    idx = 0
    for c in courses:
        data['id_' + str(idx)] = c.id
        data['name_' + str(idx)] = c.name
        idx += 1
    
    data_json = json.dumps(data)

    return HttpResponse(data_json)


def get_student_tracking(user):

    student = Student.objects.filter(id=user).get()
    
    return student.tracking.all()

#COMPROBACION DE USUARIO
def check_alexa(request, **kwargs):
    
    user = kwargs['user']
    alexa_id = kwargs['alexa_id']

    if (Student.objects.filter(username=user).exists()):
        student = Student.objects.filter(username=user).get()
        alexa_id_user = student.alexa_id
        if (alexa_id_user == alexa_id):
            return HttpResponse("{OK}")
        else:
            return HttpResponse("{ERROR: no match}")       
    else:
        return HttpResponse("{ERROR: user not found}")

#REGISTRO DE DISPOSITIVO ALEXA
def register_alexa(request, **kwargs):

    user = kwargs['user']
    alexa_id = kwargs['alexa_id']
    birthday = kwargs['birthday']

    student = Student.objects.filter(username=user).get()

    if (str(student.dateofbirth) == birthday):
        student.alexa_id = alexa_id
        student.save()
        return HttpResponse("{OK}")
    else:
        return HttpResponse("{ERROR: no match}") 

#OBTENCION DE MICROCONTENIDO
def get_microcontent(request, **kwargs):

    user = kwargs['user']
    microcontent_id = kwargs['microcontent_id']

    student = Student.objects.filter(username=user).get()
    states = student.states.all()
    state_aux = states.filter(microcontent = microcontent_id).all()[0]

    microcontent = MicroContent.objects.filter(metadata_id = microcontent_id).get()

    pre_questions = microcontent.pre_questionaire.question.all()
    pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

    data = {}
    idx = 0

    for preq in pre_questions:
        data['pre_question_' + str(idx)] = preq.question
        data['pre_first_choice_' + str(idx)] = preq.first_choice
        data['pre_second_choice_' + str(idx)] = preq.second_choice
        data['pre_third_choice_' + str(idx)] = preq.third_choice
        data['pre_correct_answer_' + str(idx)] = preq.correct_answer
        data['pre_explanation_' + str(idx)] = preq.explanation
        idx += 1

    try:
        data['media_file'] = str(microcontent.media.mediaFile)
        data['media_url'] = str(microcontent.media.url)
    except AttributeError:
        data['media'] = ''

    post_questions = microcontent.post_questionaire.question.all()
    post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

    idx = 0

    for postq in post_questions:
        data['post_question_' + str(idx)] = postq.question
        data['post_first_choice_' + str(idx)] = postq.first_choice
        data['post_second_choice_' + str(idx)] = postq.second_choice
        data['post_third_choice_' + str(idx)] = postq.third_choice
        data['post_correct_answer_' + str(idx)] = postq.correct_answer
        data['post_explanation_' + str(idx)] = postq.explanation
        idx += 1

    data_json = json.dumps(data)

    trace = Trace(microcontent=microcontent.name,action="Preview the microcontent", time=timezone.now())
    trace.save()

    student.tracking.add(trace)

    score=0
    if score == len(post_questions):
            state = 'green'
    elif score >= (len(post_questions)/2):   
        state = 'yellow'
    else:
        state = 'red' 

    state_aux.semaphore = state
    state_aux.last_update = timezone.now()
    state_aux.save()


    return HttpResponse(data_json)

#CORRECION DE MICROCONTENIDO
def get_result(request, **kwargs):

    user = kwargs['user']
    microcontent_id = kwargs['microcontent_id']
    position = kwargs['position']
    answers_string = kwargs['answers']

    student = Student.objects.filter(username=user).get()
    states = student.states.all()
    state_aux = states.filter(microcontent=microcontent_id).all()[0]

    microcontent = MicroContent.objects.filter(metadata_id = microcontent_id).get()

    score = 0
    idx = 0
    data = {}
    if (position == "pre"):
        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

        answers_splitted = answers_string.split("@")
        for answer in answers_splitted:
            text = answer.split("_")
            question = text(0)
            choice = text(1)

            if choice == 0:
                choice = pre_questions[idx].first_choice
            elif choice == 1:
                choice = pre_questions[idx].second_choice
            elif choice == 2:
                choice = pre_questions[idx].third_choice
            
            if(pre_questions[idx].correct_answer == choice):
                score = score +1
            else:
                data['question_' + str(idx)] = question
                data['explanation_' + str(idx)] = pre_questions[idx].explanation
            idx += 1

    else:
        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        answers_splitted = answers_string.split("@")
        for answer in answers_splitted:
            text = answer.split("_")
            question = text[0]
            choice = text[1]

            if choice == '0':
                choice = post_questions[idx].first_choice
            elif choice == '1':
                choice = post_questions[idx].second_choice
            elif choice == '2':
                choice = post_questions[idx].third_choice
            if(post_questions[idx].correct_answer == choice):
                score = score +1
            else:
                data['question_' + str(idx)] = question
                data['explanation_' + str(idx)] = post_questions[idx].explanation
            idx += 1
        
        if score == len(post_questions):
            state = 'green'
        elif score >= (len(post_questions)/2):   
            state = 'yellow'
        else:
            state = 'red'
            
        state_aux.semaphore = state
        state_aux.last_update = timezone.now()
        state_aux.save()
    
    

    data['score'] = score
    data_json = json.dumps(data) 

    return HttpResponse(data_json)

'''
FUNCIONES PARA BOT DE TELEGRAM
'''
#ENVIO DE MENSAJES PERSONALIZADOS A USUARIO
class sendNotificationView(generic.TemplateView):
    def post(self, request, *args, **kwargs):
        try:
            text = request.POST['message']
        except:
            text = "Ha sido dado de alta en el curso. Para empezar pulsa /siguiente"

        student_user = kwargs['user']
        student = Student.objects.filter(username=student_user).get()
        bot_token='1951453659:AAEKKSzxLr38Ntt0ToweCDbVZNKkUHMo9LU'
        chatid=student.telegram_id
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chatid}&text={text}"
        requests.get(url)
        return render(request, 'studentsmanager/notification_sent.html')    

#OBTENCION DE KEYWORDS
def get_keywords(request,**kwargs):
    telegram_id = kwargs['telegram_id']
    student = Student.objects.filter(telegram_id=telegram_id).get()
    keywords_states = student.keywords_states.all()
    keywords = []
    data = {}
    
    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0]
        if mc.keywords not in keywords:
            keyword_state = keywords_states.filter(keyword = mc.keywords).get()
            if keyword_state.score >= 3:
                keywords.append(mc.keywords)
    if len(keywords) == 0:
        return Http404('Keywords not found')
    for i in range(len(keywords)):
        data['keyword_'+str(i)]=keywords[i]
    data_json = json.dumps(data)
    return HttpResponse(data_json)

#REINICIO DE CURSO
def telegram_restart(request, **kwargs):
    data = {}
    telegram_id = kwargs['telegram_id']
    student = Student.objects.filter(telegram_id=telegram_id).get()

    course_id = int(kwargs['course_id'])
    course = Playlist.objects.filter(id = course_id).get()
    
    states = student.states.all()

    student.courses.add(course)
    
    #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
    for i in range(student.itinerary.count()):
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc = sorted_mc.microcontent.all()[0]
        if not states.filter(microcontent = mc.metadata_id).all():
            state = State(semaphore="red", last_update=timezone.now())
            state.save()
            state.microcontent.add(mc)
            student.states.add(state)

            trace = Trace(microcontent=mc.name,action="Course updated", time=timezone.now())
            trace.save()

            student.tracking.add(trace)

            try:
                keyword_state = student.keywords_states.filter(keyword = mc.keywords).get()
                keyword_state.score = 0
                keyword_state.semaphore = 'red'
                keyword_state.typeIIx3 = 0
                keyword_state.typeIIx2 = 0
                keyword_state.alreadydoneII = ''
                keyword_state.alreadydoneIII=''
                keyword_state.save()
            except:
                pass
    
    
    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0]
        state_aux = states.filter(microcontent = mc.metadata_id).all()[0]
        state_aux.semaphore = 'red'
        state_aux.last_update = timezone.now()
        state_aux.save()

        trace = Trace(microcontent=mc.name,action="Restarted the course", time=timezone.now())
        trace.save()

        student.tracking.add(trace)

        student.current_keyword = 'start'

        keyword_state = student.keywords_states.filter(keyword = mc.keywords).get()
        keyword_state.score = 0
        keyword_state.semaphore = 'red'
        keyword_state.typeIIx3 = 0
        keyword_state.typeIIx2 = 0
        keyword_state.alreadydoneII = ''
        keyword_state.alreadydoneIII = ''
        keyword_state.save()
    student.notification = True
    student.save()

    data = {}
    data['info'] = 'OK'
    data_json = json.dumps(data)
    return HttpResponse(data_json)

#OBTENCION DE ESTADOS POR KEYWORD
def get_states_keyword(request, **kwargs):
    telegram_id = kwargs['telegram_id']

    student = Student.objects.filter(telegram_id=telegram_id).get()
    if student is None:
        return Http404('User not found')
    data={}
    keywords = []
    
    keyword_states = student.keywords_states.all()
    i=0

    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0]
        
        if mc.keywords not in keywords:
            keywords.append(mc.keywords)
    for kw in keywords:
        kw_state = keyword_states.filter(keyword=kw).get()
        data['keyword' + str(i)] = kw_state.keyword
        data['score' + str(i)] = kw_state.score
        i += 1 

    trace = Trace(microcontent = 'aprendeii', action='Telegram: ask for keyword states', time=timezone.now())
    trace.save()

    student.tracking.add(trace)

    data_json = json.dumps(data)

    return HttpResponse(data_json)

#OBTENCION DE ESTADOS POR MICROCONTENIDO. YA NO SE USA
def get_state_record_telegram(request, **kwargs):

    telegram_id = kwargs['telegram_id']
    course = kwargs['course']

    student = Student.objects.filter(telegram_id=telegram_id).get()
    if student is None:
        return Http404('User not found')
    playlist = Playlist.objects.filter(id=course).get()
    states = student.states.all()

    data={}

    student.courses.add(playlist)
    #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0]
        if not states.filter(microcontent = mc.metadata_id).all():
            state = State(semaphore="red", last_update=timezone.now())
            state.save()
            state.microcontent.add(mc)
            student.states.add(state)

            trace = Trace(microcontent=mc.name,action="Course updated", time=timezone.now())
            trace.save()

            student.tracking.add(trace)
    keywords = []
    microcontents = []
    
    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0]
        microcontents.append(mc)
        if mc.keywords not in keywords:
            keywords.append(mc.keywords)

    i = 0
    #COMPROBACION DE ESTADO DE ULTIMO MICROCONTENIDO REALIZADO
    for k in keywords:
        selection = []
        levelI = False
        levelII = False
        levelIII = False
        for m in microcontents:
            if m.keywords == k:
                state_aux = states.filter(microcontent = m.metadata_id).all()[0]
                if m.level == 'I':
                    levelI = True
                elif m.level == 'II':
                    levelII = True
                elif m.level == 'III':
                    levelIII = True
        if levelI:
            for m in microcontents:
                state_aux = states.filter(microcontent = m.metadata_id).all()[0]
                if m.keywords == k and m.level == 'I':
                    data['keyword_' + str(i)] = m.keywords
                    data['microcontent_' + str(i)] = m.metadata_id
                    data['name_' + str(i)] = m.name
                    data['semaphore_' + str(i)] = state_aux.semaphore
                    data['date_' + str(i)] = str(state_aux.last_update)
                    break
            
        elif levelII:
            for m in microcontents:
                state_aux = states.filter(microcontent = m.metadata_id).all()[0]
                if m.keywords == k and m.level == 'II':
                    data['keyword_' + str(i)] = m.keywords
                    data['microcontent_' + str(i)] = m.metadata_id
                    data['name_' + str(i)] = m.name
                    data['semaphore_' + str(i)] = state.semaphore
                    data['date_' + str(i)] = str(state.last_update)
                    break
            
        elif levelIII:
            for m in microcontents:
                state_aux = states.filter(microcontent = m.metadata_id).all()[0]
                if m.keywords == k and m.level == 'III':
                    data['keyword_' + str(i)] = m.keywords
                    data['microcontent_' + str(i)] = m.metadata_id
                    data['name_' + str(i)] = m.name
                    data['semaphore_' + str(i)] = state.semaphore
                    data['date_' + str(i)] = str(state.last_update)
                    break
            
        i += 1
        

    #print(data)

    data_json = json.dumps(data)

    return HttpResponse(data_json)

#OBTENCION DE MICROCONTENIDO. SECUENCIADOR
def get_next_telegram(request, **kwargs):
    
    data = {}
    telegram_id = kwargs['telegram_id']
    
    
    if not Student.objects.filter(telegram_id=telegram_id).exists():
        return Http404('User not found')

    student = Student.objects.filter(telegram_id=telegram_id).get()
    
    states = student.states.all()
    course_id = int(kwargs['course_id'])
    course = Playlist.objects.filter(id = course_id).get()
    
    states = student.states.all()
    keyword_states = student.keywords_states.all()


    microcontents = []
    states_list = [] 
    microcontent = 'empty'
    student.courses.add(course)
    
    #funcion de actualizar el curso, necesario repasar y generar una funcion aparte
    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc = sorted_mc.microcontent.all()[0]
        if not states.filter(microcontent = mc.metadata_id).all():
            state = State(semaphore="red", last_update=timezone.now())
            state.save()
            state.microcontent.add(mc)
            student.states.add(state)

            trace = Trace(microcontent=mc.name, action="Course updated", time=timezone.now())
            trace.save()

            student.tracking.add(trace)
    
    #COMPROBACION DE LIMITE DIARIO
    today = date.today()
    if student.tracking.filter(time__year=today.year, time__month=today.month, time__day=today.day, action='Preview the microcontent').count()==12:
        trace = Trace(microcontent='aprendeii', action='Content limit achieved', time=timezone.now())
        trace.save()
        student.tracking.add(trace)
        data['limit'] = 'Limit achieved'
        data_json = json.dumps(data)
        return HttpResponse(data_json)

    #COMPROBACION DE NECESIDAD DE REPASO
    revise_keyword = 'notneeded'   
    if not student.tracking.filter(time__year=today.year, time__month=today.month, time__day=today.day, action='Finish review').exists():
        url = f"http://193.146.210.19:8000/ebisu/check_values/{student.username}/"
        response = requests.get(url)
        data = response.json()
        revise_keyword = 'notneeded'
        try:
            
            revise_keyword = data['keyword']
            if student.current_keyword != revise_keyword:
                #SI SE NECESITA REPASAR, CAMBIAMOS EL VALOR DEL ESTADO DE KEYWORD PARA QUE NOS RECOMIENDE EL MICROCONTENIDO ADICIONAL
                keyword_selected = student.keywords_states.filter(keyword=revise_keyword).get()
                keyword_selected.score = 4
                keyword_selected.typeIIx3 = 3
                keyword_selected.typeIIx2 = 0
                keyword_selected.save()
                student.current_keyword=revise_keyword
                student.save()
        
        except:
            pass 

    keywords = []
    
    for i in range(student.itinerary.count()):
        sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
        mc_aux = sorted_mc.microcontent.all()[0]
        microcontents.append(mc_aux)
        if mc_aux.keywords not in keywords:
            keywords.append(mc_aux.keywords)

    #inicio de current_keyword
    if student.current_keyword =='start':
        student.current_keyword = keywords[0]
    else:
        pass
    student.save()

    #secuenciador
    keyword_state = keyword_states.filter(keyword=student.current_keyword).get()
    if (keyword_state.score == 3 and keyword_state.typeIIx3 == 3) or keyword_state.score == 0:
        microcontent = MicroContent.objects.filter(keywords=student.current_keyword, level='I', show='yes').get()
        if keyword_state.typeIIx3 == 3:
            realimentacion = f"Como no has acertado ninguna de las 3 preguntas, te voy a pedir que vuelvas a ver el vídeo principal."
        else:
            realimentacion = f"Vamos a empezar con el tema {microcontent.keywords}. Mira el vídeo que te dejo a continuación."
        keyword_state.typeIIx3 = 0
        keyword_state.score = 0
        keyword_state.save()
        
    elif keyword_state.score >= 3 and keyword_state.typeIIx3 != 3:
        items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='II', show='yes').all())
        microcontent = random.choice(items)
        try:
            alreadydone = keyword_state.alreadydoneII.split('-')
            if len(alreadydone)-1 != len(items):
                while str(microcontent.metadata_id) in alreadydone:
                    microcontent = random.choice(items)
            else:
                keyword_state.alreadydoneII = ''
            keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
            keyword_state.save()
        except:
            while str(microcontent.metadata_id) == keyword_state.alreadydoneII:
                microcontent = random.choice(items)
            keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
            keyword_state.save()
        if keyword_state.typeIIx3 == 0:
            realimentacion = f"A continuación te voy a mostrar 3 preguntas. Empezamos con la primera:"
        elif keyword_state.typeIIx3 == 1:
            realimentacion = f"Pregunta 2:"
        elif keyword_state.typeIIx3 == 2:
            realimentacion = f"Pregunta 3:"

    elif (keyword_state.score == 4 and keyword_state.typeIIx3 == 3) or (keyword_state.score==5 and keyword_state.typeIIx2==2):
        items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='III', show='yes').all())
        microcontent = random.choice(items)
        try:
            alreadydone = keyword_state.alreadydoneIII.split('-')
            if len(alreadydone)-1 != len(items):
                while str(microcontent.metadata_id) in alreadydone:
                    microcontent = random.choice(items)
            else:
                keyword_state.alreadydoneII = ''
            keyword_state.alreadydoneIII += f"{microcontent.metadata_id}-"
            keyword_state.save()
        except:
            while str(microcontent.metadata_id) == keyword_state.alreadydoneIII:
                microcontent = random.choice(items)
            keyword_state.alreadydoneIII += f"{microcontent.metadata_id}-"
            keyword_state.save()

        
        if keyword_state.typeIIx2 == 2 or revise_keyword != 'not needed':
            realimentacion = f"Parece que necesitas repasar el tema {microcontent.keywords}. Te voy a pedir que veas el siguiente contenido."
            keyword_state.typeIIx2 = 3
            keyword_state.save()
        else:
            realimentacion = f"Como has acertado solo una de las 3 preguntas, te voy a pedir que veas el siguiente contenido."
        
    elif keyword_state.score >= 6 and ((keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 == 0) or keyword_state.typeIIx2 == 2):
        '''NUEVO'''
        if not revise_keyword == 'notneeded':
            if (keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 == 0):
                realimentacion = f"¡Enhorabuena! Lo has hecho muy bien en el tema {revise_keyword}. "
                success = 1
            elif(keyword_state.typeIIx2 == 2 and keyword_state.score == 6):
                realimentacion = f"¡Enhorabuena! Lo has hecho bien en el tema {revise_keyword}. "
                success = 0
            elif(keyword_state.typeIIx2 == 2 and keyword_state.score == 7):
                realimentacion = f"¡Enhorabuena! Lo has hecho muy bien en el tema {revise_keyword}. "
                success = 0
            else:
                realimentacion = f"¡Enhorabuena! Lo has hecho bien en el tema {revise_keyword}. "
                success = 0
            realimentacion += f"Has finalizado el repaso. Para ver tu estado en el curso dime /estado. Para empezar el siguiente tema dime /siguiente."

            for kw in keywords:
                keyword_state = keyword_states.filter(keyword=kw).get()
                if keyword_state.score < 6:
                    student.current_keyword = kw
                    student.save()
                    break
            trace = Trace(microcontent = f"Keyword:{revise_keyword}", action='Finish review', time=timezone.now())
            trace.save()
            student.tracking.add(trace)
            student.save()
            data = {}
            data['finish_recomendation'] = realimentacion
            data_json = json.dumps(data)
            return HttpResponse(data_json)
        
        for index in range(len(keywords)):
            if student.current_keyword == keywords[index]:
                try:
                    '''NUEVO'''
                    keyword = student.current_keyword
                    order = index
                    total = 1

                    trace = Trace(microcontent='aprendeii', action=f"Finished Keyword {keyword}", time=timezone.now())
                    trace.save()
                    student.tracking.add(trace)
                    student.save()

                    student.current_keyword = keywords[index+1]
                    student.save()
                    #microcontent = MicroContent.objects.filter(keywords=student.current_keyword, level='I').get()
                    if (keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 == 0):
                        realimentacion = f"¡Enhorabuena! Lo has hecho muy bien en el tema {keywords[index]}. "
                        success = 1
                    elif(keyword_state.typeIIx2 == 2 and keyword_state.score == 6):
                        realimentacion = f"¡Enhorabuena! Lo has hecho bien en el tema {keywords[index]}. "
                        success = 0
                    elif(keyword_state.typeIIx2 == 2 and keyword_state.score == 7):
                        realimentacion = f"¡Enhorabuena! Lo has hecho muy bien en el tema {keywords[index]}. "
                        success = 0
                    else:
                        success = 0
                    realimentacion += f"Para ver tu estado en el curso dime /estado. Para empezar el siguiente tema dime /siguiente."

                    url = f"http://193.146.210.19:8000/ebisu/update_model/{student.username}/{keyword}/{order}/{success}/{total}"
                    response = requests.get(url)

                    data = {}
                    data['finish_unit'] = realimentacion
                    data_json = json.dumps(data)
                    return HttpResponse(data_json)
                except:
                    '''NUEVO'''
                    keyword = student.current_keyword
                    order = index
                    total = 1

                    #microcontent = MicroContent.objects.filter(keywords=student.current_keyword, level='I').get()
                    if (keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 == 0):                        
                        success = 1
                    elif(keyword_state.typeIIx2 == 2 and keyword_state.score == 6):                        
                        success = 0
                    elif(keyword_state.typeIIx2 == 2 and keyword_state.score == 7):
                        success = 0
                    else:
                        success = 0
                    
                    url = f"http://193.146.210.19:8000/ebisu/update_model/{student.username}/{keyword}/{order}/{success}/{total}"
                    response = requests.get(url)

                    trace = Trace(microcontent='aprendeii', action='Finished course', time=timezone.now())
                    trace.save()
                    student.tracking.add(trace)
                    student.notification = False
                    student.save()
                    data['finish_course'] = 'Nothing new'
                    data_json = json.dumps(data)
                    return HttpResponse(data_json)
                break
        
    elif keyword_state.score >= 5 and keyword_state.typeIIx3 == 3 and keyword_state.typeIIx2 != 2:
        items = list(MicroContent.objects.filter(keywords=student.current_keyword, level='II', show='yes').all())
        microcontent = random.choice(items)
        try:
            alreadydone = keyword_state.alreadydoneII.split('-')
            if len(alreadydone)-1 != len(items):
                while str(microcontent.metadata_id) in alreadydone:
                    microcontent = random.choice(items)
            else:
                keyword_state.alreadydoneII = ''
            keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
            keyword_state.save()
        except:
            while str(microcontent.metadata_id) == keyword_state.alreadydoneII:
                microcontent = random.choice(items)
            keyword_state.alreadydoneII += f"{microcontent.metadata_id}-"
            keyword_state.save()
        if keyword_state.typeIIx2==0:
            realimentacion = f"Te voy a hacer otras dos preguntas del tema {microcontent.keywords}. Empezamos con la primera:" 
        elif keyword_state.typeIIx2==3:
            keyword_state.typeIIx2 = 0
            keyword_state.save()
            realimentacion = f"Te voy a hacer otras dos preguntas del tema {microcontent.keywords}. Empezamos con la primera:"
        if keyword_state.typeIIx2 == 1:
            realimentacion = f"Pregunta 2:"

    #si no tiene nada que ver, enviamos mensaje de error
    if microcontent == 'empty':
        data['error'] = 'Nothing new'
        data_json = json.dumps(data)
        return HttpResponse(data_json)

    #obtencion de datos de microcontenido
    micro_id = microcontent.metadata_id
    for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            microcontent = MicroContent.objects.filter(metadata_id = micro_id).get()
            mc = sorted_mc.microcontent.all()[0]
            if mc.name == microcontent.name:
                microcontent = mc
        
    state_aux = states.filter(microcontent = mc.metadata_id).all()[0]
    keyword_state = keyword_states.filter(keyword=microcontent.keywords).get()
    
    pre_questions = microcontent.pre_questionaire.question.all()
    pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

    data = {}
    idx = 0
    data['id'] = microcontent.metadata_id
    data['title'] = microcontent.name
    data['level'] = microcontent.level
    data['realimentacion']  = realimentacion
    
    for preq in pre_questions:
        data['pre_question_' + str(idx)] = preq.question
        data['pre_first_choice_' + str(idx)] = preq.first_choice
        data['pre_second_choice_' + str(idx)] = preq.second_choice
        data['pre_third_choice_' + str(idx)] = preq.third_choice
        data['pre_correct_answer_' + str(idx)] = preq.correct_answer
        data['pre_explanation_' + str(idx)] = preq.explanation
        idx += 1

    try:
        data['media_file'] = str(microcontent.media.mediaFile)
        data['media_url'] = str(microcontent.media.url)
        data['media_telegram'] = str(microcontent.media.id_telegram)
        data['text'] = str(microcontent.media.text)
    except AttributeError:
        data['media'] = ''

    post_questions = microcontent.post_questionaire.question.all()
    post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

    idx = 0

    for postq in post_questions:
        data['post_question_' + str(idx)] = postq.question
        data['post_first_choice_' + str(idx)] = postq.first_choice
        data['post_second_choice_' + str(idx)] = postq.second_choice
        data['post_third_choice_' + str(idx)] = postq.third_choice
        data['post_correct_answer_' + str(idx)] = postq.correct_answer
        data['post_explanation_' + str(idx)] = postq.explanation
        idx += 1

    data_json = json.dumps(data)

    trace = Trace(microcontent = microcontent.name, action="Preview the microcontent", time=timezone.now())
    trace.save()

    student.tracking.add(trace)
    student.save()
    score=0
    if score == len(post_questions):
            
        if microcontent.level == 'I':
            keyword_state.score += 3
        elif microcontent.level == 'II':
            keyword_state.score += 1
        else:
            keyword_state.score += 1
        keyword_state.save()
        state = 'green'
    elif score >= (len(post_questions)/2):   #preguntar valores duda
        state = 'yellow'
    else:
        state = 'red'

    state_aux.semaphore = state
    state_aux.last_update = timezone.now()
    state_aux.save()


    return HttpResponse(data_json)    

#OBTENCION DE MICROCONTENIDO A TRAVES DE SELECCIONA (KEYWORD + LEVEL)
def get_microcontent_telegram(request, **kwargs):

    telegram_id = kwargs['telegram_id']
    keyword = kwargs['keyword']
    level = kwargs['level']

    student = Student.objects.filter(telegram_id=telegram_id).get()
    if student is None:
        return Http404('User not found')
    
    items = list(MicroContent.objects.filter(keywords=keyword, level=level).all())
    microcontent = random.choice(items)

    pre_questions = microcontent.pre_questionaire.question.all()
    pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))

    data = {}
    idx = 0

    data['title'] = microcontent.name
    
    for preq in pre_questions:
        data['pre_question_' + str(idx)] = preq.question
        data['pre_first_choice_' + str(idx)] = preq.first_choice
        data['pre_second_choice_' + str(idx)] = preq.second_choice
        data['pre_third_choice_' + str(idx)] = preq.third_choice
        data['pre_correct_answer_' + str(idx)] = preq.correct_answer
        data['pre_explanation_' + str(idx)] = preq.explanation
        idx += 1

    try:
        data['media_file'] = str(microcontent.media.mediaFile)
        data['media_url'] = str(microcontent.media.url)
        data['media_telegram'] = str(microcontent.media.id_telegram)
        data['text'] = str(microcontent.media.text)
    except AttributeError:
        data['media'] = ''

    post_questions = microcontent.post_questionaire.question.all()
    post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

    idx = 0

    for postq in post_questions:
        data['post_question_' + str(idx)] = postq.question
        data['post_first_choice_' + str(idx)] = postq.first_choice
        data['post_second_choice_' + str(idx)] = postq.second_choice
        data['post_third_choice_' + str(idx)] = postq.third_choice
        data['post_correct_answer_' + str(idx)] = postq.correct_answer
        data['post_explanation_' + str(idx)] = postq.explanation
        idx += 1

    data_json = json.dumps(data)

    trace = Trace(microcontent=microcontent.name, action="Preview the microcontent via /selecciona", time=timezone.now())
    trace.save()

    student.tracking.add(trace)

    trace

    score=0
    if score == len(post_questions):
        state = 'green'
    elif score >= (len(post_questions)/2):   #preguntar valores duda
        state = 'yellow'
    else:
        state = 'red' 

    return HttpResponse(data_json)

#CORRECCION DE MICROCONTENIDO
def get_result_telegram(request, **kwargs):

    telegram_id = kwargs['telegram_id']
    microcontent_id = kwargs['microcontent_id']
    position = kwargs['position']
    answers_string = kwargs['answers']

    student = Student.objects.filter(telegram_id=telegram_id).get()
    if student is None:
        return Http404('User not found')
    states = student.states.all()
    state_aux = states.filter(microcontent=microcontent_id).all()[0]

       
    microcontent = MicroContent.objects.filter(metadata_id = microcontent_id).get()

    keywords_state = student.keywords_states.all()
    keyword_state = keywords_state.filter(keyword = microcontent.keywords).get()

    score = 0
    idx = 0
    data = {}
    post_questionnaire_list = []
    pre_questionnaire_list = []
    if (position == "pre"):
        pre_questions = microcontent.pre_questionaire.question.all()
        pre_questions = sorted(pre_questions, key=operator.attrgetter('order_in_questionnaire'))
        
        answers_splitted = answers_string.split("@")
        for answer in answers_splitted:
            text = answer.split("_")
            if len(text) > 1:
                question = text(0)
                choice = text(1)

                if choice == 0:
                    choice = pre_questions[idx].first_choice
                elif choice == 1:
                    choice = pre_questions[idx].second_choice
                elif choice == 2:
                    choice = pre_questions[idx].third_choice
                
                if(pre_questions[idx].correct_answer == choice):
                    score = score +1
                    score_result = 'correct'
                else:
                    data['question_' + str(idx)] = question
                    data['explanation_' + str(idx)] = pre_questions[idx].explanation
                    score_result = 'incorrect'
                idx += 1
                pre_questionnaire_list.append(score_result)
    
    else:
        
        
        post_questions = microcontent.post_questionaire.question.all()
        post_questions = sorted(post_questions, key=operator.attrgetter('order_in_questionnaire'))

        answers_splitted = answers_string.split("@")
        for answer in answers_splitted:
            text = answer.split("_")
            if len(text) > 1:

                question = text[0]
                choice = text[1]
                if choice == '0':
                    choice = post_questions[idx].first_choice
                elif choice == '1':
                    choice = post_questions[idx].second_choice
                elif choice == '2':
                    choice = post_questions[idx].third_choice
                if(post_questions[idx].correct_answer == choice):
                    score = score +1
                    score_result = 'correct'
                else:
                    data['question_' + str(idx)] = question
                    data['explanation_' + str(idx)] = post_questions[idx].explanation
                    score_result = 'incorrect'
                idx += 1
                post_questionnaire_list.append(score_result)
            
        if score == len(post_questions):
            if microcontent.level == 'I':
                keyword_state.score += 3
            elif microcontent.level == 'II':
                keyword_state.score += 1
            else:
                keyword_state.score += 1
            keyword_state.save()
            state = 'green'
        elif score >= (len(post_questions)/2):   #preguntar valores duda
            state = 'yellow'
        else:
            state = 'red'
        state_aux.semaphore = state
        state_aux.last_update = timezone.now()
        state_aux.save()

        if microcontent.level == 'II' and keyword_state.typeIIx3 != 3:
            keyword_state.typeIIx3 += 1
        else:
            keyword_state.typeIIx2 += 1
        keyword_state.save()

    pre_questionnaire_text = ''.join([str(item) for item in pre_questionnaire_list])
    post_questionnaire_text = ''.join([str(item) for item in post_questionnaire_list])

    action = 'Solves microcontent #. Q&A: ' + pre_questionnaire_text + post_questionnaire_text
    
    trace = Trace(microcontent = microcontent.name, action=action, time=timezone.now())
    trace.save()

    student.tracking.add(trace)
    student.save()
        
    data['score'] = score
    data_json = json.dumps(data) 

    return HttpResponse(data_json)

#MODIFICAR SI SE PERMITEN NOTIFICACIONES
def activate_notifications(request, **kwargs):
    telegram_id = kwargs['telegram_id']
    data= {}
    student = Student.objects.filter(telegram_id=telegram_id).get()
    if student is None:
        return Http404('User not found')
    if student.notification == True:
        student.notification = False
        data['message'] = "Has desactivado las notificaciones. A partir de ahora no recibirás avisos para participar en el curso. Para volver a activar las notificaciones dime /notificar."

    else:
        student.notification = True
        data['message']="Has activado las notificaciones. Te enviaré un aviso cuando tengas que participar en el curso. Si quieres desactivar las notificaciones dime /notificar."
    student.save()
    data_json= json.dumps(data)

    return HttpResponse(data_json)

#FUNCION DEL SCHEDULER
def periodic_task(request, **kwargs):
    today = timezone.now()
    
    students = Student.objects.filter(notification = True).all()
    
    for student in students:
        trace = student.tracking.order_by('-time').all()[0]
        diff = relativedelta(today, trace.time)
        #envio de notificacion por inactividad
        if diff.days > 2 or trace.action == 'Inactivity notification sent to user':
            bot_token='1951453659:AAEKKSzxLr38Ntt0ToweCDbVZNKkUHMo9LU'
            chatid=student.telegram_id
            text = 'Este es un recordatorio del curso Aprendeii. Dime /siguiente para seguir avanzando. Si tienes algún problema dime /comentario para contarme que pasa.'
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chatid}&text={text}"
            requests.get(url)

            action = 'Inactivity notification sent to user'
    
            trace = Trace(microcontent = 'aprendeii', action=action, time=timezone.now())
            trace.save()

            student.tracking.add(trace)
            student.save()
            
        
        today2 = datetime.now()
        yesterday = today2 - timedelta(hours=24)
        #envio de notificacion por limite de contenidos liberados
        if student.tracking.filter(time__year=yesterday.year, time__month=yesterday.month, time__day=yesterday.day, action='Preview the microcontent').count()==12:
            text = "Hoy ya puedes continuar con Aprendeii. Pulse /siguiente para continuar"
            bot_token='1951453659:AAEKKSzxLr38Ntt0ToweCDbVZNKkUHMo9LU'
            chatid=student.telegram_id
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chatid}&text={text}"
            requests.get(url)

            action = 'Limit reminder notification sent to user'
    
            trace = Trace(microcontent = 'aprendeii', action=action, time=timezone.now())
            trace.save()

            student.tracking.add(trace)
            student.save()
            


    return HttpResponse('ok')

#GUARDAR COMENTARIOS
def get_comments(request, **kwargs):
    telegram_id = kwargs['telegram_id']
    comment = kwargs['comment']

    student = Student.objects.filter(telegram_id = telegram_id).get()
    if student is None:
        return Http404('User not found')
    
    comment = Comments(comment=comment, time=timezone.now())
    comment.save()

    trace = Trace(microcontent = 'aprendeii', action=comment.comment, time=timezone.now())
    trace.save()

    student.tracking.add(trace)
    student.comments.add(comment)
    student.save()

    text = f"{student.username}: {comment.comment} "
    bot_token='5593663342:AAHthe2-ttaoZEsgBcGBne3iGqBERRQspWc'
    chatid=-753428006
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chatid}&text={text}"
    requests.get(url)

    return HttpResponse('ok')
