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


def cert_decoder(cert_string):
    with tempfile.NamedTemporaryFile() as temp:
        temp.write(cert_string)
        temp.flush()
        command = 'openssl x509 -inform der -text -in %s' % (temp.name)
        return subprocess.check_output(shlex.split(command))

def pp_loader(pp_path):
    with open(pp_path, 'rb') as provision_file:
        provision_data = provision_file.read()
        start_tag = '<?xml version="1.0" encoding="UTF-8"?>'
        stop_tag = '</plist>'
        start_index = provision_data.index(start_tag)
        stop_index = provision_data.index(stop_tag, start_index + len(start_tag)) + len(stop_tag)
        plist_data = provision_data[start_index:stop_index]
        return plistlib.readPlistFromString(plist_data)

class Cert(object):

    def __init__(self, cert_string):
        self.validity, self.uid, self.cn = self._parse_cert(cert_string)

    def _parse_cert(self, cert):
        validity, uid, cn = None, None, None
        for l in cert.splitlines():
            if "Not After : " in l:
                d = l.split(":", 1)[-1].lstrip()
                validity = time.mktime(datetime.datetime.strptime(d, '%b %d %H:%M:%S %Y %Z').timetuple())
            elif "Subject: UID=" in l:
                subject = l.split(":", 1)[-1].split(", ")
                uid, cn = subject[0].split("=")[1], subject[1].split("=")[1]
        return validity, uid, cn

    def __repr__(self):
        return self.uid + " " + self.cn

class MobileProvision(object):

    def __init__(self, pp_dict, cert_decoder):
        self.uuid = pp_dict['UUID']
        self.appid = pp_dict['Entitlements']['application-identifier'].split('.', 1)[1]
        self.expiration_date = time.mktime(pp_dict['ExpirationDate'].timetuple())
        devices_udids = pp_dict.get('ProvisionedDevices', None)
        self.udids = devices_udids or []
        self.is_appstore = (devices_udids is None)
        self.certs = []
        for c in pp_dict['DeveloperCertificates']:
            cert = Cert(cert_decoder(c.data))
            if cert.validity <= time.time():
                continue
            self.certs.append(cert)

    def __repr__(self):
        return " :: ".join([self.appid.rjust(30), str(self.is_appstore).rjust(5), self.uuid.ljust(36), time.ctime(self.expiration_date), str(self.certs)])

if __name__ == '__main__':

    desc = 'Lookup all the installed provisioning profiles and output information about them.'
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("-v", "--verbose", action="store_true", \
        help="Increase output verbosity")
    parser.add_argument("-l", "--list", default=True, type=bool, \
        help="List all available provisioning profiles and their relevant contents.")
    parser.add_argument("-a", "--appid", default=None, type=str, \
        help="The application ID to look for.")
    parser.add_argument("-w", "--wildcard", type=bool, default=False, \
        help="Wether wildcard provisioning profiles should be considered.")
    parser.add_argument("-d", "--development", type=bool, \
        help="Look for development certificates only (as opposed to production certificates).")
    parser.add_argument("-k", "--keychain", type=str, \
        help="The path to the keychain containing the certificates (improves the matching heuristic by allowing the inspection of codesigning certificates).")
    parser.add_argument("-p", "--password", type=str, \
        help="The password for the keychain (required to unlock it).")
    parser.add_argument("-m", "--mobiledevices", type=str, default=os.path.join(os.path.expanduser('~'), "Library", "MobileDevices", "Provisioning Profiles"), \
        help="The directory to look for installed provisioning profiles.")

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s::%(levelname)s::%(message)s')
    logging.getLogger().setLevel(getattr(logging, 'INFO'))
    logging.getLogger().addHandler(logging.StreamHandler())
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    args.mobiledevices = "."
    provisioning_profiles = []
    for profile in os.listdir(args.mobiledevices):
        if not os.path.isfile(profile): continue
        elif not profile.endswith("mobileprovision"): continue

        try:
            p = MobileProvision(pp_loader(profile), cert_decoder)

            if args.appid and args.appid != p.appid:
                logging.debug("Doesn't match specified appid: %s" % (profile))
                continue
            if args.development == True and p.is_appstore:
                logging.debug("Doesn't match environment: %s" % (profile))
                continue
            if args.wildcard and p.appid != "*":
                logging.debug("It's not a wildcard: %s" % (profile))
                continue
            if not p.certs:
                logging.debug("No valid certificates found: %s" % (profile))
                continue

            print p.appid
            provisioning_profiles.append(p)
        except:
            logging.error("Invalid provisioning profile: %s" % (profile))

    for p in provisioning_profiles:
        print p.uuid
