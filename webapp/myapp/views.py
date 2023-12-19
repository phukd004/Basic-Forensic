# views.py
import os
from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import MyModelForm
from .vt_api import VTScan, VTScanException

def home(request):
    return render(request, 'myapp/base.html')

def upload_file(request):
    if request.method == 'POST':
        form = MyModelForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                instance = form.save(commit=False)
                instance.save()

                vtscan = VTScan()
                vtscan.run(instance.file.path)

                os.remove(instance.file.path)

                return redirect('success')
            except VTScanException as e:
                print(f"VTScanException: {e}")
                return render(request, 'myapp/upload_failed.html')
    else:
        form = MyModelForm()

    return render(request, 'myapp/upload_file.html', {'form': form})

def success(request):
    result_file_path = os.path.join(os.path.dirname(__file__), 'result.txt')
    if os.path.exists(result_file_path):
        os.remove(result_file_path)
    return render(request, 'myapp/success.html')

def loading_screen(request):
    return render(request, 'myapp/loading_screen.html')

def upload_failed(request):
    return render(request, 'myapp/upload_failed.html')

def result(request):
    return render(request, 'myapp/result.html')

def system(request):
    return render(request, 'myapp/system.html')

def processes(request):
    return render(request, 'myapp/processes.html')

def network(request):
    return render(request, 'myapp/network.html')

def other(request):
    return render(request, 'myapp/other.html')
