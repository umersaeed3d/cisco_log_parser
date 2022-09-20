from django.shortcuts import redirect, render
from firewall.models import  CiscoLogs
from django.contrib import messages
from django.conf import settings
from django.http import HttpResponse, Http404
from django.core.files.storage import FileSystemStorage
from builtins import any as b_any
from django.core.files import File
from django.contrib.auth.models import User
from firewall.forms import CustomUserCreationForm
from django.core.exceptions import PermissionDenied
from difflib import SequenceMatcher
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import ValidationError

import os
import re
import datetime
from time import gmtime, strftime


# Create your views here.

def download(request, filename):
    if request.user.is_authenticated:
        file_path = os.path.join(settings.MEDIA_ROOT, filename)
        if os.path.exists(file_path):
            with open(file_path, 'rb') as fh:
                response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
                response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
                return response
                
        raise Http404
    else:
        raise PermissionDenied

def users_list(request):

    if request.user.is_superuser:
        data = User.objects.all()
        return render(request,'users_list.html',{'data':data})
    else:
        raise PermissionDenied

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request,'User Created')
            
            return redirect('/login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})


def dashboard(request):
    if request.user.is_authenticated:
        if request.method == "GET":
            return render(request, 'dashboard.html') 
        else:
            messages.warning(request,"Bad request : 400")
            return redirect('dashboard')
    else:
        raise PermissionDenied



def cisco_logs_history(request):

    if request.user.is_authenticated:
        if request.user.is_superuser:
            records = CiscoLogs.objects.all()
        else:
            records = CiscoLogs.objects.filter(user_id=request.user.id)
        return render(request,'logs_history.html',{'data':records})
    
    else:
        raise PermissionDenied

def password_check(request,passwd):
      
    SpecialSym =['$', '@', '#', '%']
    val = True
      
    if len(passwd) < 6:
        messages.warning(request,'length should be at least 6')
        val = False
          
    if len(passwd) > 20:
        messages.warning(request,'length should be not be greater than 8')
        val = False
          
    if not any(char.isdigit() for char in passwd):
        messages.warning(request,'Password should have at least one numeral')
        val = False
          
    if not any(char.isupper() for char in passwd):
        messages.warning(request,'Password should have at least one uppercase letter')
        val = False
          
    if not any(char.islower() for char in passwd):
        messages.warning(request,'Password should have at least one lowercase letter')
        val = False
          
    if not any(char in SpecialSym for char in passwd):
        messages.warning(request,'Password should have at least one of the symbols $@#')
        val = False
    if val:
        return val

def changePassword(request):

    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        new_password_check = request.POST.get('new_password1')
        userID = request.user.id
        max_similarity = 0.7

        user = User.objects.get(id=userID)
        
        if user.check_password(current_password):
            if new_password == new_password_check:
                if SequenceMatcher(a=new_password.lower(), b=request.user.username.lower()).quick_ratio() > max_similarity:
                    messages.warning(request,"The password is too similar to the username.")
                    return redirect('/dashboard')
                if SequenceMatcher(a=new_password.lower(), b=request.user.email.lower()).quick_ratio() > max_similarity:
                    messages.warning(request,"The password is too similar to the email.")
                    return redirect('/dashboard')
                validated = password_check(request,new_password)
                if validated == True:
                    user.set_password(new_password)
                    user.save()
                    update_session_auth_hash(request, user)
                    messages.success(request,'Password changed !')
            else:
                messages.warning(request,'Password do not match')
                
        else:
            messages.warning(request,'Current password is not corrent. Please try again')
        return redirect('/dashboard')
    


def cisco_logs(request, input_file=False):

    if request.user.is_authenticated:
        regex1 = r"(?P<timestamp>\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}).*: (?P<access>\w{4,9}) (?P<protocol>\w{3}).*dmz:(?P<srcIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/(?P<srcPort>\d*) .*dst outside:(?P<dstIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/(?P<dstPort>\d*).*"
        regex2 = r"(?P<timestamp>\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}).*: access-list .* (?P<access>\w{4,9}|\w{1,4}-\w{1,10}) (?P<protocol>\w{3}).*inside/(?P<srcIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\((.*?)\).*(?:outside|dmz)/(?P<dstIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\((.*?)\).*"
        regex3 = r"(?P<timestamp>\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}).*:.* (?P<built>\w*) (?P<protocol>\w*) (?:translation|connection) .*(?:from outside:|for outside:|from inside:|for internet:|for faddr )(?P<srcIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/(?P<srcPort>\d*).*(?:to outside:|to inside:|to identity:|to dmz:|to vlan.*:|laddr )(?P<dstIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|.*)/(?P<dstPort>\d*)"
        regex4 = r"(?P<timestamp>\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}).*: (?P<access>\w*) (?P<protocol>\w*).*(?:from |outside:)(?P<srcIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/(?P<srcPort> |\d*).*[ |:](?P<dstIP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})[ |/](?P<dstPort>\d*).*"
        uploaded_filename = False

        if request.method == 'POST':
            try:
                myfile = request.FILES['file']
                fs = FileSystemStorage()
                filename = fs.save(myfile.name, myfile)
                uploaded_file_url = fs.url(filename)
                uploaded_filename = filename

                record = CiscoLogs(input_file=filename,user_id=request.user.id)
                record.save()

            except BaseException as e:
                messages.warning(request,str(e))
                return redirect('dashboard')

        if uploaded_filename != False:
            file_name = uploaded_filename
        elif input_file != False:
            file_name = input_file
        else:
            file_name = "cisco_logs.txt"

        #format = ["timestamp", "access", "protocol", "srcIP", "srcPort", "dstIP", "dstPort"]

        path = os.path.abspath(os.path.dirname(__name__))
        filename = path+"/firewall/media/"+file_name
        with open(filename) as f:
                log = f.read()

        res = []

        regex = [regex1, regex2, regex3, regex4]
        for reg in regex:
            logs = re.findall(reg,log)
            for i in logs:
                res.append(i)


        protocol_count = []
        dstPort_count = []
        srcIP_count = []
        dstIP_count = []
        
        for i in res:
            
            protocol = sum(1 for d in res if d[2] == i[2])
            p = { 'value':protocol,'name': i[2]}
            if p.get('name') not in protocol_count:
                protocol_count.append(p)
            
            dstPort = sum(1 for d in res if d[6] == i[6])
            d = {'value':dstPort,'name': i[6]}
            if d.get('name') not in dstPort_count:
                dstPort_count.append(d)

            srcIP = sum(1 for d in res if d[3] == i[3])
            s = { 'value':srcIP, 'name': i[3]}
            if s.get('name') not in srcIP_count:
                srcIP_count.append(s)


            dstIP = sum(1 for d in res if d[5] == i[5])
            di = {'value':dstIP, 'name': i[5]}
            if di.get('name') not in dstIP_count:
                dstIP_count.append(di)
            
        protocolData = [dict(t) for t in {tuple(d.items()) for d in protocol_count}]
        dstPortData = [dict(t) for t in {tuple(d.items()) for d in dstPort_count}]
        srcIPData = [dict(t) for t in {tuple(d.items()) for d in srcIP_count}]
        dstIPData = [dict(t) for t in {tuple(d.items()) for d in dstIP_count}]


    # filtering important data    
        dstIP_others_count = 0
        loopCount = 0
        for i in dstIPData:
            
            if i.get("value") == 1:
                dstIP_others_count += 1
                del dstIPData[loopCount]
            loopCount +=1

        dstIPData.append({'value':dstIP_others_count,'name':'Others'})

        srcIP_others_count = 0
        loopCount = 0
        for i in srcIPData:
            
            if i.get("value") == 1:
                srcIP_others_count += 1
                del srcIPData[loopCount]
            loopCount +=1

        srcIPData.append({'value':srcIP_others_count,'name':'Others'})
        
        return render(request, 'cisco_logs.html',{'data':res,'protocolData':protocolData,'dstPortData':dstPortData,'srcIPData':srcIPData,'dstIPData':dstIPData})
    else:
        raise PermissionDenied

def home(request):

    if request.method == 'GET':
        return redirect('/login')
    else:
        return redirect('/dashboard')
        

        