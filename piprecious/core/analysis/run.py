import json
import pprint
import yara
from optparse import OptionParser

from mitmproxy import io
from mitmproxy.exceptions import FlowReadException


def get_host_from_headers(flow):
    for k, v in flow.request.headers.items():
        if k == 'Host':
            return v


def check_payload(flow, payload, rules, results):
    matches = rules.match(data = payload)
    if len(matches) > 0:
        host = get_host_from_headers(flow)
        if host not in results:
            results[host] = {
                # 'url': flow.request.url,
                'ip': flow.request.host,
                'matches': {str(m): {'count': 1, 'tags': m.tags} for m in matches},
            }
        else:
            for m in matches:
                if str(m) in results[host]['matches']:
                    results[host]['matches'][str(m)]['count'] += 1
                else:
                    results[host]['matches'][str(m)]['count'] = 1
    return results


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-f', '--flow-dump', dest = 'flow_file', help = 'flow file path')
    parser.add_option('-r', '--rules', dest = 'rules_file', help = 'rules file path')

    (options, args) = parser.parse_args()
    rules = yara.compile(filepath = options.rules_file)
    results = {}
    with open(options.flow_file, "rb") as logfile:
        freader = io.FlowReader(logfile)
        pp = pprint.PrettyPrinter(indent = 2)
        try:
            for flow in freader.stream():
                results = check_payload(flow, flow.request.url, rules, results)
                if flow.request.method in ["POST", "PUT", "PATCH"]:
                    results = check_payload(flow, flow.request.get_text(strict = False), rules, results)
        except FlowReadException as e:
            print("Flow file corrupted: {}".format(e))

    print(json.dumps(results, indent = 2))
