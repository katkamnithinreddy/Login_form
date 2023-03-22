from base64 import urlsafe_b64decode, urlsafe_b64encode
from email.message import EmailMessage
from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from login import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import *
from django.utils.encoding import *
from . tokens import generate_token
# Create your views here.
def home(request):
    return render(request,"index.html")
def signup(request):
    if request.method=="POST":
        username=request.POST['username']
        fname=request.POST['fname']
        lname=request.POST['lname']
        email=request.POST['email'] 
        pw=request.POST['pw'] 
        cpw=request.POST['cpw']

        if User.objects.filter(username=username):
            messages.error(request,"Username already exist Pleasemtry other username")
            return redirect('home')
        if User.objects.filter(email=email):
            messages.error(request,"email already used")
            return redirect('home') 
        if len(username)>10:
            messages.error(request,"USername must be under 10 characters") 
        if len(pw)<6:
            messages.error(request,"Please enter Strong password")
        if pw!=cpw:
            messages.error(request,"Passwords must be same") 
        if not username.isalnum():
            messages.error(request,"Username must be alphabets") 
            return redirect('home')


        user=User.objects.create_user(username,email,pw) 
        user.first_name=fname
        user.last_name=lname
        user.save()
        messages.success(request,"Your Account is Successfully Created. ") 

        ''' subject="Welcome to KNRRR group of industries" 
        message='Hello '+user.first_name+"!! \n"+"Welcome to KNRRR group of industries \n Thank you visiting our website \n We have also sent you a confrimation mail ,  please confirm your mail address in order to activate your account. \n\n\n Thanking you \n\n\n KATKAM NITHIN REDDY" 
        from_email=settings.EMAIL_HOST_USER 
        to_list=[user.email] 
        send_mail(subject,message,from_email,to_list,fail_silently=True)

        current_site=get_current_site(request)
        email_subject="Confirm your email @katkamnithi"
        message2=render_to_string('email.html',{
            'name':user.first_name,
            'domain':current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user.email],
        )
        email.fail_silently = True
        email.send()'''


        return redirect('signin')

    return render(request,"signup.html")

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_b64decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        user = None

    if user is not None and generate_token.check_token(user,token):
        user.is_active = True
        # user.profile.signup_confirmation = True
        user.save()
        login(request,user)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')

def signin(request):
    if request.method=="POST":
        username=request.POST['username'] 
        pw=request.POST['pw'] 
        user=authenticate(username=username,password=pw)
        if user is not None:
            login(request,user) 
            fname=user.first_name
            return render(request,"index.html",{'fname':fname})
        else:
            messages.error(request,"Please check your details!")
            return render(request,'signin.html')

    return render(request,"signin.html")


def signout(request):
    logout(request)
    messages.success(request,"logged out sucess")
    return redirect('home')