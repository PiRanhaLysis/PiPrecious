from django.http.response import Http404, JsonResponse, HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser

from core.models import *
from core.serializers import *


def index(request):
    try:
        experiments = Experiment.objects.order_by('name')
    except Experiment.DoesNotExist:
        raise Http404("experiments does not exist")
    return render(request, 'experiment_list.html', {'experiments': experiments})


def application_list(request):
    try:
        applications = Application.objects.order_by('name')
    except Experiment.DoesNotExist:
        raise Http404("applications does not exist")
    return render(request, 'application_list.html', {'applications': applications})


def smartphone_list(request):
    try:
        smartphones = Smartphone.objects.order_by('name')
    except Experiment.DoesNotExist:
        raise Http404("smartphones does not exist")
    return render(request, 'smartphone_list.html', {'smartphones': smartphones})


def device_list(request):
    try:
        devices = IoTDevice.objects.order_by('name')
    except Experiment.DoesNotExist:
        raise Http404("devices does not exist")
    return render(request, 'device_list.html', {'devices': devices})


@csrf_exempt
def api_smartphone(request):
    if request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = SmartphoneSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)


@csrf_exempt
def api_experiment_get(request, pk):
    try:
        snippet = Experiment.objects.get(pk=pk)
    except Experiment.DoesNotExist:
        return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = ExperimentSerializer(snippet)
        return JsonResponse(serializer.data)


@csrf_exempt
def api_smartphone_get(request, pk):
    try:
        snippet = Smartphone.objects.get(pk=pk)
    except Smartphone.DoesNotExist:
        return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = SmartphoneSerializer(snippet)
        return JsonResponse(serializer.data)


@csrf_exempt
def api_application_get(request, pk):
    try:
        snippet = Application.objects.get(pk=pk)
    except Application.DoesNotExist:
        return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = ApplicationSerializer(snippet)
        return JsonResponse(serializer.data)