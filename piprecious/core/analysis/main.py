import json
import pprint
import tempfile
import requests
import yara

from core.analysis.har import flow_to_har
from core.models import Experiment

from mitmproxy import io
from mitmproxy.exceptions import FlowReadException


def geoip(ip):
    r = requests.get('https://get.geojs.io/v1/ip/geo/%s.json' % ip)
    if r.status_code != 200:
        return
    obj = r.json()
    result = {}
    if 'country' in obj:
        result['country'] = obj['country']
    if 'country_code' in obj:
        result['country_code'] = obj['country_code']
    if 'city' in obj:
        result['city'] = obj['city']
    if 'region' in obj:
        result['region'] = obj['region']
    if 'latitude' in obj:
        result['latitude'] = obj['latitude']
    if 'longitude' in obj:
        result['longitude'] = obj['longitude']
    if 'organization' in obj:
        result['organization'] = obj['organization']
    return result

def get_host_from_headers(flow):
    for k, v in flow.request.headers.items():
        if k == 'Host':
            return v


def check_payload(flow, payload, rules, results):
    matches = rules.match(data = payload)
    if len(matches) > 0:
        host = get_host_from_headers(flow)
        if host not in results:
            # pprint.pprint(flow.request)
            results[host] = {
                # 'url': flow.request.url,
                'ip': flow.request.host,
                'secure': flow.request.url.startswith('https'),
                'matches': {str(m): {'count': 1, 'tags': m.tags} for m in matches},
            }
        else:
            for m in matches:
                if str(m) in results[host]['matches']:
                    results[host]['matches'][str(m)]['count'] += 1
                else:
                    results[host]['matches'][str(m)] = {'count': 1}
    return results


def find_markers(experiment):
    rules = experiment.rules
    if experiment.application:
        rules += experiment.application.rules
    if experiment.smartphone:
        rules += experiment.smartphone.rules

    rules = yara.compile(source = rules)
    results = {}
    for session in experiment.session_set.all():
        if session.flow_file is None:
            continue
        with tempfile.NamedTemporaryFile() as f:
            for chunk in session.flow_file.file.chunks():
                f.write(chunk)
            f.seek(0)

            with open(f.name, "rb") as logfile:
                freader = io.FlowReader(logfile)
                pp = pprint.PrettyPrinter(indent = 2)
                try:
                    for flow in freader.stream():
                        results = check_payload(flow, flow.request.url, rules, results)
                        print(flow.request.url)
                        if flow.request.method in ["POST", "PUT", "PATCH"]:
                            results = check_payload(flow, flow.request.get_text(strict = False), rules, results)
                except FlowReadException as e:
                    print("Flow file corrupted: {}".format(e))
    return results


def merge_dns_markers(dns, markers):
    for m in markers:
        if m in dns:
            markers[m]['dns'] = dns[m]
        else:
            for d in dns:
                if dns[d]['ip'] == m:
                    markers[m]['dns'] = dns[d]
                    markers[m]['dns']['domain'] = dns[d]
    for m in markers:
        if 'dns' not in markers[m]:
            markers[m]['dns'] = geoip(markers[m]['ip'])
    return markers


def compute_full_report(experiment_id):
    try:
        experiment = Experiment.objects.get(pk = experiment_id)
    except Experiment.DoesNotExist as e:
        return

    dns = {}

    for session in experiment.session_set.all():
        for analysis in session.networkanalysis_set.all():
            for dns_query in analysis.dnsquery_set.all():
                dns[dns_query.domain] = {
                    'ip': dns_query.address,
                    'domain': dns_query.domain,
                    'country': dns_query.country,
                    'region': dns_query.region,
                    'city': dns_query.city,
                    'organization': dns_query.organization,
                }
    results = find_markers(experiment)
    results = merge_dns_markers(dns, results)
    experiment.report = results

    experiment.save()

