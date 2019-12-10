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
import json
import hashlib
import sys

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

def pretty_print(pprofile):
    print colorize('blue', '------------------------------------------')
    print "Name: %s" % (pprofile.name)
    print "AppId: %s" % (pprofile.appid)
    print "UUID: %s" % (pprofile.uuid)
    print "Development?: %s" % (pprofile.development)
    print "PushNotifications?: %s" % (pprofile.pushnotifications)
    print "Expiration: %s" % (check_expiration(pprofile.expiration_date))
    print "Attached Certificates:"
    for cert in pprofile.certs:
        print "\t%s %s" % (cert.cn, check_expiration(cert.validity))
    for cert in pprofile.certs_expired:
        print "\t%s %s" % (cert.cn, check_expiration(cert.validity))

def get_profiles(pp_dir=os.path.join(
        os.path.expanduser('~'),
        "Library",
        "MobileDevice",
        "Provisioning Profiles"
    )):
    profiles = []
    for profile in os.listdir(pp_dir):
        pp_fullpath = os.path.join(pp_dir, profile)
        if not pp_fullpath.endswith("mobileprovision"):
            continue
        profiles.append(MobileProvision(pp_fullpath))
    return profiles

def run_cmd(cmd):
    return subprocess.check_output(shlex.split(cmd)).decode("unicode_escape").encode("latin1")

def get_codesign_identities(keychain):
    command = '/usr/bin/security find-identity -p codesigning -v %s' % (keychain)
    return run_cmd(command)

def check_expiration(date):
    color = 'green'
    warning_threshold = 1296000 # 2 weeks
    critical_threshold = 648000 # 1 week
    delta = date - time.time()
    time_string = ''
    if  delta < critical_threshold:
        logging.critical("Expiration date is very close!")
        color = 'fail'
    elif delta < warning_threshold:
        logging.warning("Expiration date is coming soon...")
        color = 'warning'
    time_string += (colorize(color, time.ctime(date)))
    return time_string


class Cert(object):

    @staticmethod
    def decode(cert_bin_data):
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(cert_bin_data)
            temp.flush()
            command = 'openssl x509 -inform der -text -in %s' % (temp.name)
            return run_cmd(command)

    def __init__(self, shasum, cert_bin_data):
        self.shasum = shasum.upper()
        self.validity, self.uid, self.cn = self.parse_cert(Cert.decode(cert_bin_data))

    def parse_cert(self, cert):
        validity, uid, cn = None, None, None
        for line in cert.splitlines():
            if "Not After : " in line:
                date = line.split(":", 1)[-1].lstrip()
                timetuple = datetime.datetime.strptime(date, '%b %d %H:%M:%S %Y %Z').timetuple()
                validity = time.mktime(timetuple)
            elif "Subject: UID=" in line:
                attrs = self.parse_dn(line)
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

    @staticmethod
    def pp_loader(pp_path):
        with open(pp_path, 'rb') as provision_file:
            provision_data = provision_file.read()
            start_tag = '<?xml version="1.0" encoding="UTF-8"?>'
            stop_tag = '</plist>'
            start_index = provision_data.index(start_tag)
            stop_index = provision_data.index(stop_tag,
                                              start_index + len(start_tag)) + len(stop_tag)
            plist_data = provision_data[start_index:stop_index]
            return plistlib.readPlistFromString(plist_data)

    def __init__(self, pp_fullpath):
        pp_dict = MobileProvision.pp_loader(pp_fullpath)
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
        for cert_bin in pp_dict['DeveloperCertificates']:
            shasum = hashlib.sha1(cert_bin.data).hexdigest()
            cert = Cert(shasum, cert_bin.data)
            if cert.validity <= time.time():
                logging.debug('%s: Old certificate found.', self.uuid)
                self.certs_expired.append(cert)
            else:
                logging.debug('%s: Up-to-date certificate found.', self.uuid)
                self.certs.append(cert)


def main(pp_dir, app_id='*', wildcard=False, production=False, keychain=None):

    profiles = []
    identities = None

    if keychain:
        identities = get_codesign_identities(keychain)

    for profile in get_profiles(pp_dir):

        if app_id != '*':
            # Ensure we match the user-specified AppId
            if app_id != profile.appid:
                logging.debug("%s: Doesn't match specified app_id (%s != %s).",
                              profile.uuid, app_id, profile.appid)
                continue
            # Ensure we match development or distribution parameter
            if profile.development == production:
                logging.debug("%s: Doesn't match environment (%s).", profile.uuid, "pro" if production else "dev")
                continue

        # Must have at least one valid certificate
        if not profile.certs:
            logging.debug("%s: No valid certificates found.", profile.uuid)
            continue

        # If identities are a thing, try to match those
        if identities:
            matches = [cert for cert in profile.certs \
                      if cert.cn in identities and cert.shasum.upper() in identities.upper()]
            if matches:
                profiles.append(profile)
            else:
                logging.error("%s: No certificates match the codesigning identities.", profile.uuid)
        else:
            profiles.append(profile)

    output = []
    # Make sure the wildcard provisioning profiles come last
    for profile in sorted(profiles, key=lambda x: x.appid, reverse=wildcard):
        for cert in profile.certs:
            if identities and cert.shasum not in identities:
                continue
            output.append({
                'uuid': profile.uuid,
                'name': profile.name,
                'shasum': cert.shasum,
                'teamid': profile.teamid,
            })
    return output


if __name__ == '__main__':

    desc = 'Lookup all the installed provisioning profiles and output information about them.'
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("-v", "--verbose", action="store_true", \
        help="Increase output verbosity")
    parser.add_argument("-a", "--appid", default=None, type=str, \
        help="The application ID to look for.")
    parser.add_argument("-w", "--wildcard", action="store_false", \
        help="Heuristic will prefer wildcard provisioning profiles above others.")
    parser.add_argument("-p", "--production", action="store_true", \
        help="Look for development certificates only (as opposed to production certificates).")
    parser.add_argument("-k", "--keychain", type=str, \
        help="The path of the keychain (must be unlocked).Improves the profile matching heuristic.")
    parser.add_argument("-m", "--mobiledevices", type=str, \
                        default=os.path.join(
                            os.path.expanduser('~'),
                            "Library", "MobileDevice", "Provisioning Profiles"), \
        help="The directory to look for installed provisioning profiles.")
    parser.add_argument("-r", "--report", action="store_true", \
        help="Generate a nice looking report instead of generating output for an application.")
    parser.add_argument("-j", "--json", action="store_true", \
        help="Output in JSON format.")

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s::%(levelname)s::%(message)s')
    logging.getLogger().setLevel(getattr(logging, 'INFO'))
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)


    if args.keychain:
        if not os.path.isfile(args.keychain):
            raise SystemExit('Unable find keychain file: %s' % (args.keychain))

    if not os.path.isdir(args.mobiledevices):
        logging.critical('Directory containing provisioning profiles doesn\'t exist.')
        logging.critical('Directory: %s.', args.mobiledevices)
        logging.critical('Specify it with -m <provisioning profile directory>.')
        raise SystemExit

    if args.report:
        [pretty_print(p) for p in get_profiles(args.mobiledevices)]
        sys.exit(0)

    provisioning_profiles = main(args.mobiledevices,
                                 args.appid,
                                 args.wildcard,
                                 args.production,
                                 args.keychain)

    if args.json:
        print json.dumps(provisioning_profiles)
    else:
        for p in provisioning_profiles:
            print '@'.join([p['uuid'], p['name'], p['shasum'], p['teamid']])
