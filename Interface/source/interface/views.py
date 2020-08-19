from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.views.decorators.http import require_http_methods
import sys
sys.path.append("..")
from AutoSecMeg.manage import Manager

@csrf_exempt
@require_http_methods(["POST"])
def create_equipment(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.equipment.create(equipmentModel=jsondata.get('equipmentModel'), context=jsondata.get('context'))
        return JsonResponse(status=200, data={'results':res})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def remove_equipment(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.equipment.remove(equipmentUUID=jsondata.get('equipmentUUID'))
        return JsonResponse(status=200, data={'results':'Removed'})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema and make sure the URI exists. {repr(e)}.'})

@csrf_exempt
@require_http_methods(["POST"])
def equipment_list_service_on_device(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.equipment.list_service_on_device(deviceUUID=jsondata.get('deviceUUID'))
        return JsonResponse(status=200, data={'results': res})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def enable_service(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.service.enable(serviceUUID=jsondata.get('serviceUUID'), userUUID=jsondata.get('userUUID'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def suspend_service(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.service.suspend(serviceUUID=jsondata.get('serviceUUID'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def disable_service(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.service.disable(serviceUUID=jsondata.get('serviceUUID'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})


@csrf_exempt
@require_http_methods(["POST"])
def recommend_auth(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.service.recommend_auth(rejectedServiceUUID=jsondata.get('rejectedServiceUUID'), userUUID=jsondata.get('userUUID'), Lock=jsondata.get('Lock', False))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def add_policy(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.policy.add_policy(policyDict=jsondata.get('policyDict'), policyClass=jsondata.get('policyClass'))
        return JsonResponse(status=200, data={'results': res})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def remove_policy(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.policy.remove_policy(policyUUID=jsondata.get('policyUUID'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def bind_policy_to_individual(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.policy.bind_policy_to_individual(individualURI=jsondata.get('individualURI'), policyURI=jsondata.get('policyURI'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def remove_policy_of_individual(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.policy.remove_policy_of_individual(individualURI=jsondata.get('individualURI'), policyURI=jsondata.get('policyURI'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})


@csrf_exempt
@require_http_methods(["POST"])
def report_threat(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.event.report_threat(equipmentUUID=jsondata.get('equipmentUUID'), Threat_Class=jsondata.get('Threat_Class'), envUUID=jsondata.get('envUUID', None))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def remove_threat(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.event.remove_threat(ThreatUUID=jsondata.get('ThreatUUID'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

@csrf_exempt
@require_http_methods(["POST"])
def add_context(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.context.add_context(contextIndividual=jsondata.get('contextIndividual'), contextClass=jsondata.get('contextClass'), dataproperty=jsondata.get('dataproperty', None), data=jsondata.get('data', None), datatype=jsondata.get('datatype', 'Literal'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

def bind_context_to_individual(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.context.bind_context_to_individual(individualURI=jsondata.get('individualURI'), contextURI=jsondata.get('contextURI'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

def remove_context_of_individual(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.context.bind_context_to_individual(individualURI=jsondata.get('individualURI'), contextURI=jsondata.get('contextURI'))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})

def add_user(request):
    body_unicode = request.body.decode('utf-8')
    jsondata = json.loads(body_unicode)
    manager = Manager()
    try:
        res = manager.user.add_user(user=jsondata.get('user'), context=jsondata.get('context', {}))
        return JsonResponse(status=200, data={'results': json.dumps(res)})
    except Exception as e:
        return JsonResponse(status=400, data={'results': f'Bad Request. Please check the JSON schema. {repr(e)}'})