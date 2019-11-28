#!/usr/bin/env python3

import sys
import json
import socket
import tldextract
try:
    import urllib.request as ureq
except:
    import urllib2 as ureq


socket.setdefaulttimeout(10)

PULSES = []
DEV_FLAG = False
class indicators(object):
    def __init__(self):
        self.FILE = 'file'
        self.DOMAIN = 'domain'
        self.HOSTNAME = 'hostname'
        self.IP = 'IPv4'
INDICATOR_TYPES = indicators()
DOMAIN = 'domain'
HOSTNAME = 'hostname'

""" Pulse Item """
class IndicatorPulses(object):
    def __init__(self):
        self.malware_families = []
        self.name = ''
        self.description = ''
        self.created = ''
        self.modified = ''
        self.groups = []
        self.refs = []
        self.adversary = ''

    def __str__(self):
        return "%s_%s" % (self.name[0:16], self.groups)

""" Split string every nth char """
def _split_every_n (string, n):
	return [string[i:i + n] for i in range(0, len(string), n)]

""" Check if the item is a domain or a subdomain """
def _check_domain_or_host(value):
    a = tldextract.extract(value)
    if a.subdomain == '':
        return DOMAIN
    else:
        return HOSTNAME

""" Build OTX's URL """
def _build_url(indicator_value, indicator_type):
    url_base = "https://otx.alienvault.com/api/v1/indicators/"
    url_base += "%s" % indicator_type
    url_base += "/%s/general" % indicator_value
    return url_base


def getPulses(indicator, indicator_type, silent=True):
    global PULSES
    PULSES = []

    # Check if this is a domain or a hostname (subdomain)
    if indicator_type == DOMAIN or indicator_type == HOSTNAME:
        indic_type = _check_domain_or_host(indicator)
        if indic_type != indicator_type:
            if not silent: sys.stdout.write("Switching indicator type from %s to %s.\n" % (indicator_type, indic_type))
    else:
        indic_type = indicator_type

    # If DEV, load testing JSON.
    if DEV_FLAG:
        json_response = eval(open('general.json', 'r').read())
    else:
        fp = ureq.urlopen(_build_url(indicator, indic_type))
        mybytes = fp.read()
        json_response = json.loads(mybytes.decode("utf8"))
        fp.close()

    # Check if there are pulses.
    try:
        pulse_count = json_response['pulse_info']['count']
    except:
        if not silent: sys.stderr.write("Could not fetch pulse count. Probably indicator not found.\n")
        return False


    if pulse_count != 0:
        if not silent: sys.stdout.write("This indicator appears in %s pulses.\n" % pulse_count)
    else:
        if not silent: sys.stderr.write("Indicator does not appear in any pulses.\n")
        return False

    # Build a PULSE object to add to entire list.
    for pulse in json_response['pulse_info']['pulses']:
        thisPulse = IndicatorPulses()
        thisPulse.name = pulse['name'].strip()
        thisPulse.description = pulse['description'].strip()
        thisPulse.created = pulse['created']
        thisPulse.modified = pulse['modified']
        thisPulse.refs = pulse['references']
        thisPulse.adversary = pulse['adversary']

        malwares = []
        for i in pulse['malware_families']:
            j = i['display_name'].strip()
            if j != '':
                malwares.append(j)
        thisPulse.malware_families = malwares

        groups = []
        for i in pulse['groups']:
            j = i['name'].strip()
            if j != '':
                groups.append(j)
        thisPulse.groups = groups
        PULSES.append(thisPulse)

    return PULSES
