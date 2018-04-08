import json
import os
import subprocess
import tempfile


def flow_file_to_har(flow_file):
    har_dump = os.path.dirname(os.path.relpath(__file__)) + '/har_dump.py'
    mitmdump = os.environ['VIRTUAL_ENV'] + '/bin/mitmdump'
    with tempfile.NamedTemporaryFile() as har_file:
        subprocess.check_output(
            '%s -s ./%s -r %s --set hardump=%s' % (mitmdump, har_dump, flow_file, har_file.name), shell = True)
        har_file.seek(0)
        return json.load(open(har_file.name, 'r'))


def flow_to_har(flow):
    with tempfile.NamedTemporaryFile() as flow_file:
        for chunk in flow.chunks():
            flow_file.write(chunk)
        flow_file.seek(0)
        return flow_file_to_har(flow_file.name)
