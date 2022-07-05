from inspect import trace
from django.contrib import messages
from django.contrib.auth.forms import PasswordResetForm, AuthenticationForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin, SuccessURLAllowedHostsMixin, \
    INTERNAL_RESET_SESSION_TOKEN, LoginView
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
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

from rest_framework import viewsets


from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
#añadida tras error en signup
from django.core.mail import send_mail
from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import generic

from usersmanager.forms import UserCreateForm
from usersmanager.serializers import UserSerializer

from studentsmanager.models import Student, Trace, State
from authoringtool.models import MicroContent, Playlist, SortedMicrocontent

import csv

UserModel = get_user_model()

# API classes
class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer

#PANTALLA DE INICIO DE USUARIO AUTENTICADO
class HomeView(TemplateView):

    def get(self, request, *args, **kwargs):
        return render(request, 'usersmanager/user_page.html')

#COMPROBACION DE DATOS --> AL EDITAR SE ENVIA A EditUserDataView
class UserDataView(TemplateView):
    def get(self, request):
        template_name = 'usersmanager/user_data_show_and_edit.html'
        return render(request, template_name)

#login
class LoginView(SuccessURLAllowedHostsMixin, FormView):
    """
        Display the login form and handle the login action.
        """
    form_class = AuthenticationForm
    authentication_form = None
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'registration/login_as_teacher.html'
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

#modificacion de contraseña
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
    return render(request, 'usersmanager/password_change.html', {
        'form': form
    })


# The following are the accounts views #
#REGISTRO DE USUARIO: actualmente no funciona por exigencias de seguridad de google. no tenemos acceso al envio de correos por gmail. Solucion: replicado de solucion en studentsmanager
class SignUp(generic.CreateView):
    form_class = UserCreateForm
    success_url = reverse_lazy('login_as_teacher')
    template_name = 'registration/login_as_teacher.html'

    def form_valid(self, form):
        user = form.save()
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.is_staff = True
            user.save()

            current_site = get_current_site(self.request)
            mail_subject = 'Activate the new user account.'
            message = render_to_string('usersmanager/acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            email = EmailMessage(
                mail_subject, message, to=[settings.EMAIL_ADMIN_RECEIVER]  # admin email
            )
            email.send()
            return render(self.request, 'usersmanager/confirm_registration.html')

        else:
            form = UserCreateForm()
        return render(self.request, 'resgistration/login_as_teacher.html', {'form': form})

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
        message = render_to_string('usersmanager/user_link_confirmation.html', {
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

#MODIFICACION DE DATOS DE USUARIO
class EditUserDataView(generic.TemplateView):
    template_name = "usersmanager/user_data_show_and_edit.html"

    def get(self, request, *args, **kwargs):
        return render(request, template_name="usersmanager/user_data_show_and_edit.html")

    def post(self, request, *args, **kwargs):
        try:
            uid = kwargs['id']
            user = UserModel._default_manager.get(pk=uid)
            
            user.username=request.POST['userName']
            user.first_name = request.POST['firstName']
            user.last_name = request.POST['lastName']
            user.email = request.POST['email']

            user.save()

        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        
        return render(request, template_name="usersmanager/user_data_show_and_edit.html")

#VISUALIZACION DE USUARIOS MATRICULADOS A UNA UNIDAD
class StudentsListViewPlaylist(generic.TemplateView):
    template_name = "usersmanager/students_enrolled_playlist.html"

    def get(self, request, *args, **kwargs):
        course = int(kwargs['playlist_id'])
        students = Student.objects.filter(courses = course).all()
        

        return render(request, 'usersmanager/students_enrolled_playlist.html', {"course": course, "students": students})
        
        
#VISUALIZACION DE USUARIOS MATRICULADOS A UN MICROCONTENIDO
class StudentsListView(generic.TemplateView):
    template_name = "usersmanager/students_enrolled.html"

    def get(self, request, *args, **kwargs):
        course = int(kwargs['playlist_id'])
        mc_id = int(kwargs['mc_id'])
        microcontent = MicroContent.objects.filter(metadata_id = mc_id).get()
        students = Student.objects.filter(courses = course).all()
        
        
        return render(request, 'usersmanager/students_enrolled.html', {"microcontent": microcontent,
                                                                        "students": students})

#GENERACION DE CSV CON TODAS LAS TRAZAS POR USUARIO
def export_all(request, **kwargs):
    response = HttpResponse(content_type='text/csv')

    user = (kwargs['user'])
    student = Student.objects.filter(username=user).get()
    
    traces = []
    
    traces_per_mc = list(student.tracking.all())
            
    for tr in traces_per_mc:
        trace = {'mc': tr.microcontent, 'action':tr.action, 'time': tr.time }
        traces.append(trace)

    #escritura de fichero csv
    writer = csv.writer(response)
    writer.writerow(['Microcontent', 'Action', 'Time'])

    for trace in traces:
        writer.writerow([trace['mc'], trace['action'], trace['time']])

    response['Content-Disposition'] = 'attachment; filename="traces"' + user + '".csv"'
    return response

#GENERACION DE CSV CON TODAS LAS TRAZAS DE UN MICROCONTENIDO POR USUARIO
def export(request, **kwargs):
    response = HttpResponse(content_type='text/csv')

    user = (kwargs['user'])
    student = Student.objects.filter(username=user).get()

    mc_id = int(kwargs['mc_id'])
    microcontent = MicroContent.objects.filter(metadata_id = mc_id).get()

    traces = student.tracking.filter(microcontent=microcontent.name).all()

    #escritura de fichero csv
    writer = csv.writer(response)
    writer.writerow(['Action', 'Time'])

    for trace in traces.values_list('action', 'time'):
        writer.writerow(trace)

    response['Content-Disposition'] = 'attachment; filename="traces"' + user + '".csv"'
    return response

#VISUALIZACION DE TODAS LAS TRAZAS POR USUARIO
class ViewGeneralTraces(generic.TemplateView):
    template_name = "usersmanager/student_tracking_general.html"

    def get(self, request, *args, **kwargs):
        user = (kwargs['user'])
        student = Student.objects.filter(username=user).get()

        aux_playlist = []
        for i in range(student.itinerary.count()):
            sorted_mc = SortedMicrocontent.objects.filter(id=student.itinerary.all()[i].id).get()
            mc_aux = sorted_mc.microcontent.all()[0]
            aux_playlist.append(mc_aux)

        traces = []
        #for mc in aux_playlist:
        #    microcontent=MicroContent.objects.filter(name=mc.name, show='yes').get()
        traces_per_mc = list(student.tracking.all())
            
        for tr in traces_per_mc:
            trace = {'mc': tr.microcontent, 'action':tr.action, 'time': tr.time }
            traces.append(trace)

        return render(request, 'usersmanager/student_tracking_general.html', {"traces": traces, "student":student})

#VISUALIZACION DE TODAS LAS TRAZAS DE UN MICROCONTENIDO POR USUARIO 
class ViewTracesView(generic.TemplateView):
    template_name = "usersmanager/student_tracking.html"

    def get(self, request, *args, **kwargs):

        user = (kwargs['user'])
        student = Student.objects.filter(username=user).get()

        mc_id = int(kwargs['mc_id'])
        microcontent = MicroContent.objects.filter(metadata_id = mc_id).get()

        traces = student.tracking.filter(microcontent=microcontent.name).all()
        
        
        return render(request, 'usersmanager/student_tracking.html', {"microcontent": microcontent,
                                                                      "traces": traces,
                                                                      "student": student})

#VISUALIZACION DE COMENTARIOS 
class viewCommentsView(generic.TemplateView):
    def get(self, request, *args, **kwargs):
        students = Student.objects.all()
        comments = []
        for student in students:
            comments_per_student = list(student.comments.all())
            for comment in comments_per_student:
                cm = {'student': student.username, 'comment':comment.comment, 'time': comment.time }
                comments.append(cm)

        return render(request, 'usersmanager/students_comments.html', {"comments": comments})

#VISUALIZACION DE COMENTARIOS POR USUARIO
class viewCommentsperStudentView(generic.TemplateView):
    def get(self, request, *args, **kwargs):
        user = (kwargs['user'])
        student = Student.objects.filter(username=user).get()
        comments = []
        
        comments_per_student = list(student.comments.all())
        for comment in comments_per_student:
            cm = {'student': student.username, 'comment':comment.comment, 'time': comment.time }
            comments.append(cm)

        return render(request, 'usersmanager/student_comments.html', {"comments": comments})