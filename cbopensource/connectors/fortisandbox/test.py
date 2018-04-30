#!/usr/bin/env python
from apiclient_virustotal import VirusTotalAnalysisClient as VtClient
from requests import Session
from os import environ as env
import sys

if __name__ == "__main__":
    cmd = sys.argv[1]
    vt = VtClient(Session(), env['VT_API_KEY'])
    if (cmd == "report"):
        print vt.get_report(resource_hash=sys.argv[2])
    elif (cmd == "scan"):
        print vt.submit_file(stream=open(sys.argv[2], "rb"))
    elif (cmd == "rescan"):
        print vt.rescan_hash(resource_hash=sys.argv[2])
