import json

from core.analysis.har import flow_to_har
from core.models import Experiment


def find_markers(experiment):
    import urllib
    from urllib.parse import urlparse
    markers = experiment.markers
    # From the smartphone
    if experiment.application is not None:
        markers['application.handle'] = experiment.application.handle
    if experiment.smartphone is not None:
        markers = {**markers, **experiment.smartphone.markers}
        markers['smartphone.imei'] = experiment.smartphone.serial
    print(json.dumps(markers, indent = 2))
    results = {}
    for session in experiment.session_set.all():
        har = flow_to_har(session.flow_file.file)
        for entry in har['log']['entries']:
            url = urllib.parse.unquote(entry['request']['url'])
            parsed_uri = urlparse(url)
            domain = parsed_uri.netloc
            secure = parsed_uri.scheme == 'https'
            if domain not in results:
                results[domain] = {
                    'secure': secure,
                    'data': []
                }
            request = ''
            if entry['request']['method'] == 'POST':
                request = entry['request']['postData']['text']
            for k in markers:
                if markers[k] in url or markers[k] in request:
                    if k not in results[domain]['data']:
                        results[domain]['data'].append(k)
    return results


def merge_dns_markers(dns, markers):
    for m in markers:
        markers[m]['dns'] = dns[m]
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
                    'country': dns_query.country,
                    'region': dns_query.region,
                    'city': dns_query.city,
                    'organization': dns_query.organization,
                }
    results = find_markers(experiment)
    results = merge_dns_markers(dns, results)
    experiment.report = results
    experiment.save()

