import requests
from xmlrpc.client import ServerProxy
from redis import Redis

def endpoint_request(prtc, addr, rqm):
    """
    Send request to a communication endpoint.
    :param prtc: Communication protocol HTTP/RPC/MQTT
    :param addr: Endpoint address
    :param rqm: Request model dict (payload)
    :return: Request result
    """
    #Dummy data
    return 4
    if prtc == 'HTTP':
        res = requests.get(f'http://{addr}', headers=rqm.get('headers'), data=rqm.get('payload'))
        return res.text
    elif prtc == 'RPC':
        rpc = ServerProxy(f'http://{addr}')
        res = eval(f"rpc.{rqm.get('function')}({rqm.get('parameter')})")
        return res
    elif prtc == 'MQTT':
        redis = Redis(host='redis', port=6379)
        return redis.get('addr')

