#!/usr/bin/env python
# -*- coding: utf-8 -*-

import plistlib
import os
import tempfile
import datetime
import time
import subprocess
import shlex
import logging
import argparse
import re

import hashlib

def colorize(color, string):
    colors = {
        'header': '\033[95m',
        'blue': '\033[94m',
        'green': '\033[92m',
        'warning': '\033[93m',
        'fail': '\033[91m',
        'endcolor': '\033[0m',
        'bold': '\033[1m',
        'underline': '\033[4m',
    }
    return "%s%s%s" % (colors[color], string, colors['endcolor'])

def pretty_print(p):
    print colorize('blue', '------------------------------------------')
    print "Name: %s" % (p.name)
    print "AppId: %s" % (p.appid)
    print "UUID: %s" % (p.uuid)
    print "Development?: %s" % (p.development)
    print "PushNotifications?: %s" % (p.pushnotifications)
    print "Expiration: %s" % (check_expiration(p.expiration_date))
    print "Attached Certificates:"
    for c in p.certs:
        print "\t%s %s" % (c.cn, check_expiration(c.validity))
    for c in p.certs_expired:
        print "\t%s %s" % (c.cn, check_expiration(c.validity))

def get_codesign_identities(keychain):
    command = '/usr/bin/security find-identity -p codesigning -v %s' % (keychain)
    return subprocess.check_output(shlex.split(command)).decode("unicode_escape").encode("latin1")

def check_expiration(date):
    color = 'green'
    warning_threshold = 1296000 # 2 weeks
    critical_threshold = 648000 # 1 week
    delta = date - time.time()
    s = ''
    if  delta < critical_threshold:
        logging.critical("Expiration date is very close!")
        color = 'fail'
    elif delta < warning_threshold:
        logging.warning("Expiration date is coming soon...")
        color = 'warning'
    s += (colorize(color, time.ctime(date)))
    return s


class Cert(object):

    def __init__(self, shasum, cert_string):
        self.shasum = shasum.upper()
        self.validity, self.uid, self.cn = self._parse_cert(cert_string)

    def _parse_cert(self, cert):
        validity, uid, cn = None, None, None
        for l in cert.splitlines():
            if "Not After : " in l:
                d = l.split(":", 1)[-1].lstrip()
                validity = time.mktime(datetime.datetime.strptime(d, '%b %d %H:%M:%S %Y %Z').timetuple())
            elif "Subject: UID=" in l:
                attrs = self.parse_dn(l)
                uid = attrs['UID']
                cn = attrs['CN']
        return validity, uid, cn

    def parse_dn(self, string_dn):
        attrs = {}
        curr = ""
        for match in re.split("([A-Z]+)=", string_dn):
            match = match.strip()
            if re.match("^[A-Z]+$", match):
                curr = match
            else:
                attrs[curr] = match.rstrip(",")
        return attrs


class MobileProvision(object):

    def __init__(self, pp_fullpath):
        pp_dict = self.pp_loader(pp_fullpath)
        self.uuid = pp_dict['UUID']
        self.name = pp_dict['Name']
        self.teamid = pp_dict['TeamIdentifier'][0]
        self.appid = pp_dict['Entitlements']['application-identifier'].split('.', 1)[1]
        self.expiration_date = time.mktime(pp_dict['ExpirationDate'].timetuple())
        self.udids = pp_dict.get('ProvisionedDevices', None) or []
        # Determines whether the Xcode debugger can attacxh to the App
        # A heuristic used to know if this is a distribution or a development
        # provisioning profile
        self.development = pp_dict['Entitlements']['get-task-allow']
        self.pushnotifications = False
        try:
            self.apsenvironment = pp_dict['Entitlements']['aps-environment']
        except KeyError:
            pass
        self.certs = []
        self.certs_expired = []
        for c in pp_dict['DeveloperCertificates']:
            shasum = hashlib.sha1(c.data).hexdigest()
            cert = Cert(shasum, self.cert_decoder(c.data))
            if cert.validity <= time.time():
                logging.debug("%s: Old certificate found." % (self.uuid))
                self.certs_expired.append(cert)
            else:
                logging.debug("%s: Up-to-date certificate found." % (self.uuid))
                self.certs.append(cert)

    def pp_loader(self, pp_path):
        with open(pp_path, 'rb') as provision_file:
            provision_data = provision_file.read()
            start_tag = '<?xml version="1.0" encoding="UTF-8"?>'
            stop_tag = '</plist>'
            start_index = provision_data.index(start_tag)
            stop_index = provision_data.index(stop_tag, start_index + len(start_tag)) + len(stop_tag)
            plist_data = provision_data[start_index:stop_index]
            return plistlib.readPlistFromString(plist_data)


    def cert_decoder(self, cert_string):
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(cert_string)
            temp.flush()
            command = 'openssl x509 -inform der -text -in %s' % (temp.name)
            return subprocess.check_output(shlex.split(command)).decode("unicode_escape").encode("latin1")


if __name__ == '__main__':

    desc = 'Lookup all the installed provisioning profiles and output information about them.'
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("-v", "--verbose", action="store_true", \
        help="Increase output verbosity")
    parser.add_argument("-a", "--appid", default=None, type=str, \
        help="The application ID to look for.")
    parser.add_argument("-w", "--wildcard", action="store_false", \
        help="Wether wildcard provisioning profiles should be prioritized when determining the best profile.")
    parser.add_argument("-p", "--production", action="store_true", \
        help="Look for development certificates only (as opposed to production certificates).")
    parser.add_argument("-k", "--keychain", type=str, \
        help="The path of the keychain (must be unlocked prior with 'security unlock-keychain'). Improves the profile matching heuristic.")
    parser.add_argument("-m", "--mobiledevices", type=str, default=os.path.join(os.path.expanduser('~'), "Library", "MobileDevice", "Provisioning Profiles"), \
        help="The directory to look for installed provisioning profiles.")
    parser.add_argument("-r", "--report", action="store_true", \
        help="Generate a nice looking report instead of generating output for an application.")

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s::%(levelname)s::%(message)s')
    logging.getLogger().setLevel(getattr(logging, 'INFO'))
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)


    identities = None
    if args.keychain:
        if not os.path.isfile(args.keychain):
            raise SystemExit('Unable find keychain file: %s' % (args.keychain))
        identities = get_codesign_identities(args.keychain)

    if not os.path.isdir(args.mobiledevices):
        raise SystemExit('Unable to find directory containing provisioning profiles: %s' % (args.mobiledevices))

    provisioning_profiles = []
    for profile in os.listdir(args.mobiledevices):
        pp_fullpath = os.path.join(args.mobiledevices, profile)
        if not os.path.isfile(pp_fullpath): continue
        elif not profile.endswith("mobileprovision"): continue

        p = MobileProvision(pp_fullpath)

        # When in report mode, just show the info
        if args.report:
            pretty_print(p)
            continue

        if p.appid != '*':
            if args.appid and args.appid != p.appid:
                logging.debug("%s: Doesn't match specified appid (%s)" % (p.uuid, p.appid))
                continue

            if args.production and p.development:
                logging.warning("%s: Doesn't match environment (%s)" % (p.uuid, "pro"))
                continue
            elif not args.production and p.development == False:
                logging.warning("%s: Doesn't match environment (%s)" % (p.uuid, "dev"))
                continue

        if not p.certs:
            logging.warning("%s: No valid certificates found" % (p.uuid))
            continue

        if identities:
            for c in p.certs:
                if c.cn in identities and c.shasum.upper() in identities.upper():
                    provisioning_profiles.append(p)
                    break
                else:
                    logging.error("%s: Looks good, but no certificates match the codesigning identities available within the keychain." % (p.uuid))
        else:
            provisioning_profiles.append(p)

    # Make sure the wildcard provisioning profiles come last
    for p in sorted(provisioning_profiles, key=lambda x: x.appid, reverse=args.wildcard):
        for c in p.certs:
            print '@'.join([p.uuid, p.name, c.shasum, p.teamid])
