#!/usr/bin/python2

# This little script pulls all the packages from a phone and creates MD5 and SHA1 hashes of these
# packages so that they may be compared to a malicious APK database. This version does not require
# a rooted device to function.
# *Prerequisites:* drozer, adb, pwntools.

# Copyright 2017 Nagravision SA, all rights reserved.
# Licensed under the [Apache License, Version 2.0](LICENSE)

import                                  argparse
from termcolor import                   colored
from drozer.connector import            ServerConnector
from drozer.console.console import      Console
from drozer.console.session import      Session
from pydiesel.api.protobuf_pb2 import   Message
import                                  hashlib
from collections import                 namedtuple
import                                  os
import                                  os.path
from pprint import                      pprint
from                                    pwn import *
from time import                        sleep
import                                  sys

parser = argparse.ArgumentParser(description = "Extract android APK's by keyword.")
parser.add_argument("--no-adb-forward",
                    help = ("[Optional] By default, the script sets up adb to forward traffic from "
                            "drozer; this flag disables it."),
                    action = "store_true",
                    default = False)
parser.add_argument("--thorough",
                    help = ("[Optional] Rather than call drozer's MD5 sum function, download the"
                            "packages and run MD5 and SHA1 sums on local computer"),
                    action = "store_true",
                    default = False)

PackageInfo = namedtuple("PackageInfo", "name apk_path permissions uid gid raw")

def hash_file(apk_file):
    if os.path.exists(apk_file):
        hash_md5 = hashlib.md5()
        hash_sha256 = hashlib.sha256()
        with open(apk_file, "rb") as cur_file:
            for chunk in iter(lambda: cur_file.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
        return hash_md5.hexdigest(), hash_sha256.hexdigest()
    else:
        return "", ""

def get_session():
    cur_console = Console()
    arguments   = cur_console._parser.parse_args(["console", "connect"])
    device      = cur_console._Console__get_device(arguments)
    server      = cur_console._Console__getServerConnector(arguments)
    response    = server.startSession(device, None)
    packages    = []

    if response.type == Message.SYSTEM_RESPONSE and \
       response.system_response.status == Message.SystemResponse.SUCCESS:
        session_id = response.system_response.session_id
        session = Session(server, session_id, arguments)
        return session
    else:
        return None
    

def get_pkg_info(session):
    packages = []
    if session is not None:
        list_module = session._Session__module("app.package.list")
        for pkg in list_module.packageManager().getPackages():
            app = pkg.applicationInfo
            cur_package = {"package":   app.packageName,
                           "apk_path":  app.publicSourceDir}
            packages.append(cur_package)
    else:
        print("Session not created!")
    return packages

def download_pkg(session, source, dest):
    if session is not None:
        file_module          = session._Session__module("tools.file.download")
        file_argument_parser = argparse.ArgumentParser()
        file_module.add_arguments(file_argument_parser)
        arguments            = file_argument_parser.parse_args([source, dest])
        file_module.execute(arguments)

def get_md5_checksums(session, package_info = None):
    file_module = session._Session__module("tools.file.md5sum")
    with open("package_hashes.txt", "w") as hashes_file:
        for cur_package in package_info:
            checksum_arg_parser = argparse.ArgumentParser()
            file_module.add_arguments(checksum_arg_parser)
            arguments = checksum_arg_parser.parse_args([cur_package["apk_path"]])
            md5_sum = file_module.md5sum(arguments.target)
            hashes_file.write("{}: {}\n".format(cur_package["package"], md5_sum))
            hashes_file.flush()

def get_apk_files(session, package_info = None):
    if not os.path.exists("packages"):
        os.mkdir("packages")
    with open("package_hashes.txt", "w") as hashes_file:
        os.chdir("packages")
        for cur_package in package_info:
            cur_package_name = cur_package["package"]
            cur_package_path = cur_package["apk_path"]
            log.info("Downloading APK for {}".format(cur_package_name))
            if cur_package_name != "":
                cur_apk_path = cur_package_path
                cur_apk_dest = "{}.apk".format(cur_package_name)
                try:
                    download_pkg(session    = session,
                                 source     = cur_apk_path,
                                 dest       = cur_apk_dest)
                    md5_hash, sha256_hash = hash_file(cur_apk_dest)
                    hashes_file.write("{}: {} {}\n".format(cur_package_name, md5_hash, sha256_hash))
                    hashes_file.flush()
                except Exception:
                    log.warning(sys.exc_info()[0])
                    log.warning("Problem downloading {}. Skipped.".format(cur_package_name))
        os.chdir("..")

if __name__ == "__main__":
    print(colored("""If you are not getting any results, please check the following:
- Make sure you can connect via adb
- Make sure you have drozer on your Android device
- Make sure drozer is enabled
- Make sure traffic is forwarded with adb (e.g. adb forward tcp:31415 tcp:31415)""", "red"))

    args = parser.parse_args()
    if not args.no_adb_forward:
        process(["adb", "forward", "tcp:31415", "tcp:31415"])
    session = get_session()
    pkg_info = get_pkg_info(session)
    if args.thorough:
        check_function = get_apk_files
    else:
        check_function = get_md5_checksums
    check_function(session = session, package_info = pkg_info)
