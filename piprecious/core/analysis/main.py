import json
import pprint
import tempfile
import yara

import requests
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
from phorcys.inspectors.dump_inspector import DumpInspector
from phorcys.inspectors.yara_inspector import YaraInspector
from phorcys.loaders.flow import FlowLoader

from core.models import Experiment


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
    for h in flow['request']['headers']:
        if str(h['name']).lower() == 'host':
            return h['value']


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


def compute_flow_details(session):
    rules = session.experiment.rules
    if session.experiment.application:
        rules += session.experiment.application.rules
    if session.experiment.smartphone:
        rules += session.experiment.smartphone.rules

    if session.flow_file is not None:
        with tempfile.NamedTemporaryFile() as flow_file:
            for chunk in session.flow_file.file.chunks():
                flow_file.write(chunk)
            flow_file.seek(0)
            flows = FlowLoader(flow_file.name)
            flows.load()
            di = DumpInspector(flows, [YaraInspector(rules)])
            di.inspect()
            return flows
    return None


def get_ip_address(host_or_ip):
    import socket
    try:
        socket.inet_aton(host_or_ip)
        return host_or_ip
    except socket.error:
        return socket.gethostbyname(host_or_ip)


def compute_full_report(experiment_id):
    try:
        experiment = Experiment.objects.get(pk = experiment_id)
    except Experiment.DoesNotExist as e:
        return None

    dns = {}
    results = {}
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
    for session in experiment.session_set.all():
        flows = compute_flow_details(session)
        if flows is None:
            continue
        for f in flows:
            host = get_host_from_headers(f)
            if host not in results:
                results[host] = {
                    'ip': get_ip_address(f['request']['host']),
                    'secure': f['request']['url'].startswith('https'),
                    'rules': {},
                }

            flow_rules = f['inspection']['rules']
            for rule_name, rule in flow_rules.items():
                if rule_name not in results[host]['rules']:
                    results[host]['rules'][rule_name] = rule
                else:
                    results[host]['rules'][rule_name]['count'] += rule['count']

    results = merge_dns_markers(dns, results)
    experiment.report = results

    return experiment.save()
