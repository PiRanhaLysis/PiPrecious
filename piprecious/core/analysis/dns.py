import pyshark
import requests

from core.models import *


def geoip(ip):
    r = requests.get('https://get.geojs.io/v1/ip/geo/%s.json' % ip.address)
    if r.status_code != 200:
        return
    obj = r.json()
    if len(ip.country) == 0 and 'country' in obj:
        ip.country = obj['country']
    if len(ip.country_code) == 0 and 'country_code' in obj:
        ip.country_code = obj['country_code']
    if len(ip.city) == 0 and 'city' in obj:
        ip.city = obj['city']
    if len(ip.region) == 0 and 'region' in obj:
        ip.region = obj['region']
    if len(ip.latitude) == 0 and 'latitude' in obj:
        ip.latitude = obj['latitude']
    if len(ip.longitude) == 0 and 'longitude' in obj:
        ip.longitude = obj['longitude']
    if len(ip.organization) == 0 and 'organization' in obj:
        ip.organization = obj['organization']
    ip.save()


def analyze_dns(session_id, force):
    print('analyze_dns')
    print(type(session_id))
    print(session_id)
    session = Session.objects.get(pk = str(session_id))

    network_analysis = session.networkanalysis_set.first()
    if network_analysis is None:
        network_analysis = NetworkAnalysis(session = session)
        network_analysis.save(force_insert = True)
        print(network_analysis.pk)

    # Remove previous DNS analysis
    try:
        DNSQuery.objects.filter(network_analysis = network_analysis).delete()
    except Exception:
        pass

    # Download pcap file
    with tempfile.NamedTemporaryFile(delete = True) as pcap_file:
        for chunk in session.pcap_file.file.chunks():
            pcap_file.write(chunk)
        cap = pyshark.FileCapture(pcap_file.name)
        for pkt in cap:
            try:
                if pkt.dns and pkt.dns.qry_name and pkt.dns.a:
                    qry, created = DNSQuery.objects.get_or_create(network_analysis = network_analysis, domain = pkt.dns.qry_name, address = pkt.dns.a)
                    if created or force:
                        geoip(qry)
            except AttributeError:
                pass
