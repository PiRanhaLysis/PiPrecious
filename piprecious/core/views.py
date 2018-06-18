import mimetypes
from concurrent.futures.thread import ThreadPoolExecutor

from django.contrib.auth.decorators import login_required
from django.http.response import Http404, JsonResponse, HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.parsers import JSONParser

from core.analysis.dns import analyze_dns
from core.analysis.har import flow_to_har
from core.analysis.main import compute_full_report, compute_flow_details
from core.serializers import *


@login_required
def index(request):
    try:
        experiments = Experiment.objects.order_by('name')
    except Experiment.DoesNotExist as e:
        raise Http404("experiments does not exist")
    return render(request, 'experiment_list.html', {'experiments': experiments})


@login_required
def experiment_list(request):
    try:
        experiments = Experiment.objects.order_by('name')
    except Experiment.DoesNotExist as e:
        raise Http404("experiments does not exist")
    return render(request, 'experiment_list.html', {'experiments': experiments})


@login_required
def application_list(request):
    try:
        applications = Application.objects.order_by('name')
    except Experiment.DoesNotExist as e:
        raise Http404("applications does not exist")
    return render(request, 'application_list.html', {'applications': applications})


@login_required
def smartphone_list(request):
    try:
        smartphones = Smartphone.objects.order_by('name')
    except Experiment.DoesNotExist as e:
        raise Http404("smartphones does not exist")
    return render(request, 'smartphone_list.html', {'smartphones': smartphones})


@login_required
def device_list(request):
    try:
        devices = IoTDevice.objects.order_by('name')
    except Experiment.DoesNotExist as e:
        raise Http404("devices does not exist")
    return render(request, 'device_list.html', {'devices': devices})


@login_required
def session_details(request, pk):
    try:
        session = Session.objects.get(pk = pk)
        t = None
        if session.flow_file is not None:
            har = flow_to_har(session.flow_file.file)
            t = namedtuple('GenericDict', har.keys())(**har)
    except Exception as e:
        raise Http404("session does not exist")
    return render(request, 'session_details.html', {'session': session, 'har': t})


@login_required
def flow_details(request, pk):
    try:
        session = Session.objects.get(pk = pk)

        flows = compute_flow_details(session)

        if flows is not None:
            return render(request, 'flow_details.html',
                          {'experiment': session.experiment, 'session': session, 'flows': json.dumps(flows.json())})
        return render(request, 'flow_details.html', {'flows': ''})
    except Exception as e:
        print(e)
        raise Http404("session does not exist")


def parse_raw_parameters(params):
    parameters = ['ro.build.version.incremental', 'ro.build.fingerprint', 'ro.mtk.hardware', 'ro.hardware',
                  'ro.build.host', 'ro.mediatek.version.release', 'ro.build.display.id', 'ro.product.cpu.abi',
                  'ro.build.tags', 'ro.custom.build.version', 'ro.build.id', 'ro.build.date.utc', 'ro.build.user',
                  'ro.product.model']
    lines = params.split('\n')
    rules = 'rule smartphone_attributes: mobile fingerprint {\n\tstrings:\n'
    for l in lines:
        if len(l) > 2:
            print(l)
            k = l.split('": "')[0].replace('"', '')
            v = l.split('": "')[1].replace('"', '')
            if len(v) > 5 and k in parameters:
                rules += '\t\t$%s = "%s"\n' % (k.replace('.', '_'), v)
    rules += '\tcondition:\n\t\t any of them\n}\n'
    return rules


def create_additional_smartphone_rules(s):
    # Todo add mac addresses
    rules = 'rule smartphone_imei: mobile imei pii {\n\tstrings:\n\t\t$imei = "%s"\n\tcondition:\n\t\t$imei\n}\n' % s.imei
    rules += 'rule smartphone_aid: mobile android_id pii {\n\tstrings:\n\t\t$aid = "%s"\n\tcondition:\n\t\t$aid\n}\n' % s.serial
    if len(s.phone_number) >= 10:
        rules += 'rule smartphone_phone_number: mobile phone_number pii {\n\tstrings:\n\t\t$number = "%s"\n\tcondition:\n\t\t$number\n}\n' % s.phone_number
    return rules


@csrf_exempt
@api_view(['POST'])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def api_smartphone(request):
    """
    Register a new smartphone
    :param request:
    :return:
    """
    if request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = SmartphoneSerializer(data = data)
        if serializer.is_valid():
            s = serializer.save()
            rules = parse_raw_parameters(s.raw_parameters)
            rules += create_additional_smartphone_rules(s)
            s.rules = rules
            s.save()
            return JsonResponse(serializer.data, status = 201)
        return JsonResponse(serializer.errors, status = 400)


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def api_experiment_get(request, pk):
    try:
        snippet = Experiment.objects.get(pk = pk)
    except Experiment.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        serializer = ExperimentSerializer(snippet)
        return JsonResponse(serializer.data)


@csrf_exempt
@api_view(['POST'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_experiment_session(request, pk):
    try:
        Experiment.objects.get(pk = pk)
    except Experiment.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = SessionSerializer(data = data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status = 201)
        return JsonResponse(serializer.errors, status = 400)


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_smartphone_get(request, pk):
    try:
        snippet = Smartphone.objects.get(pk = pk)
    except Smartphone.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        serializer = SmartphoneSerializer(snippet)
        return JsonResponse(serializer.data)


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_device_get(request, pk):
    try:
        snippet = IoTDevice.objects.get(pk = pk)
    except IoTDevice.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        serializer = IoTDeviceSerializer(snippet)
        return JsonResponse(serializer.data)


@csrf_exempt
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_application_get(request, pk):
    try:
        snippet = Application.objects.get(pk = pk)
    except Application.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        serializer = ApplicationSerializer(snippet)
        return JsonResponse(serializer.data)


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_apk_get(request, pk):
    if request.method == 'GET':
        try:
            application = Application.objects.get(pk = pk)
        except Application.DoesNotExist as e:
            return JsonResponse({'error': str(e)}, status = 404)
        try:
            apk = APKFile.objects.get(pk = application.apk.pk)
        except Application.DoesNotExist as e:
            return JsonResponse({'error': str(e)}, status = 404)

        with tempfile.NamedTemporaryFile() as apk_file:
            file_size = 0
            for chunk in apk.file.chunks():
                apk_file.write(chunk)
                file_size += len(chunk)
            try:
                apk_file.seek(0)
                content_type = mimetypes.guess_type(str(apk.file))[0]
                response = HttpResponse(apk_file.read(), content_type = content_type)
                response['Content-Disposition'] = 'attachment; filename=%s.apk' % pk
                response['Content-Length'] = file_size
                return response
            except Exception as e:
                return JsonResponse({'error': str(e)}, status = 500)


@csrf_exempt
@api_view(['GET', 'POST'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_flow(request, pk):
    try:
        session = Session.objects.get(pk = pk)
    except Session.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'POST' and request.FILES['file'] is not None:

        # har = flow_to_har(session.flow_file.file)
        # find_markers(har, Experiment.objects.get(session = session.pk))

        if session.flow_file is not None:
            return JsonResponse({'error': 'This session already has a flow file'}, status = 500)
        try:
            ff = FlowFile(name = pk, file = request.FILES['file'])
            ff.save()
            session.flow_file = ff
            session.save()
            # har = flow_to_har(session.flow_file)
            # print(har)
            # print(type(har))
            # session.flow_file.json = har
            # session.flow_file.save()
            return JsonResponse({'mgs': 'success'}, status = 201)
        except Exception as e:
            return JsonResponse({'err': str(e)}, status = 500)

    elif request.method == 'GET':
        with tempfile.NamedTemporaryFile() as flow_file:
            file_size = 0
            for chunk in session.flow_file.file.chunks():
                flow_file.write(chunk)
                file_size += len(chunk)
            try:
                flow_file.seek(0)
                content_type = mimetypes.guess_type(str(session.flow_file.file))[0]
                response = HttpResponse(flow_file.read(), content_type = content_type)
                response['Content-Disposition'] = 'attachment; filename=%s.flow' % pk
                response['Content-Length'] = file_size
                return response
            except Exception as e:
                return JsonResponse({'error': str(e)}, status = 500)


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication,))
@permission_classes((IsAuthenticated,))
def api_flow_har(request, pk):
    try:
        session = Session.objects.get(pk = pk)
    except Session.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        har = flow_to_har(session.flow_file.file)
        try:
            response = HttpResponse(json.dumps(har, indent = 2), content_type = 'application/json')
            return response
        except Exception as e:
            return JsonResponse({'error': str(e)}, status = 500)


@csrf_exempt
@api_view(['GET', 'POST'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_pcap(request, pk):
    try:
        session = Session.objects.get(pk = pk)
    except Session.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)
    if request.method == 'POST' and request.FILES['file'] is not None:
        if session.pcap_file is not None:
            return JsonResponse({'error': 'This session already has a pcap file'}, status = 500)
        try:
            ff = PCAPFile(name = pk, file = request.FILES['file'])
            ff.save()
            session.pcap_file = ff
            session.save()
            with ThreadPoolExecutor(max_workers = 1) as e:
                e.submit(analyze_dns, session.pk, True)
            return JsonResponse({'mgs': 'success'}, status = 201)
        except Exception as e:
            print(e)
            return JsonResponse({'err': str(e)}, status = 500)

    elif request.method == 'GET':
        with tempfile.NamedTemporaryFile() as pcap_file:
            file_size = 0
            for chunk in session.pcap_file.file.chunks():
                pcap_file.write(chunk)
                file_size += len(chunk)
            try:
                pcap_file.seek(0)
                content_type = mimetypes.guess_type(str(session.pcap_file.file))[0]
                response = HttpResponse(pcap_file.read(), content_type = content_type)
                response['Content-Disposition'] = 'attachment; filename=%s.pcap' % pk
                response['Content-Length'] = file_size
                return response
            except Exception as e:
                return JsonResponse({'error': str(e)}, status = 500)


@csrf_exempt
@api_view(['GET', 'POST'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def api_bt(request, pk):
    try:
        session = Session.objects.get(pk = pk)
    except Session.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)
    if request.method == 'POST' and request.FILES['file'] is not None:
        if session.bluetooth_dump is not None:
            return JsonResponse({'error': 'This session already has a flow file'}, status = 500)
        try:
            ff = BluetoothDump(name = pk, file = request.FILES['file'])
            ff.save()
            session.bluetooth_dump = ff
            session.save()
            return JsonResponse({'mgs': 'success'}, status = 201)
        except Exception as e:
            return JsonResponse({'err': str(e)}, status = 500)

    elif request.method == 'GET':
        with tempfile.NamedTemporaryFile() as bluetooth_dump:
            file_size = 0
            for chunk in session.bluetooth_dump.file.chunks():
                bluetooth_dump.write(chunk)
                file_size += len(chunk)
            try:
                bluetooth_dump.seek(0)
                content_type = mimetypes.guess_type(str(session.bluetooth_dump.file))[0]
                response = HttpResponse(bluetooth_dump.read(), content_type = content_type)
                response['Content-Disposition'] = 'attachment; filename=%s-bt.pcap' % pk
                response['Content-Length'] = file_size
                return response
            except Exception as e:
                return JsonResponse({'error': str(e)}, status = 500)


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def create_report(request, pk):
    try:
        Experiment.objects.get(pk = pk)
    except Experiment.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        compute_full_report(pk)
        experiment = Experiment.objects.get(pk = pk)
        return render(request, 'report.html', {'experiment': experiment, 'report': experiment.report})


@csrf_exempt
@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def view_report(request, pk):
    try:
        experiment = Experiment.objects.get(pk = pk)
    except Experiment.DoesNotExist as e:
        return JsonResponse({'error': str(e)}, status = 404)

    if request.method == 'GET':
        return render(request, 'report.html', {'experiment': experiment, 'report': experiment.report})
