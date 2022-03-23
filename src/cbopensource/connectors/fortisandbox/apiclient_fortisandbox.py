#!/usr/bin/env python

import logging
import os
from . import api_fortisandbox
from base64 import b64encode, b64decode
log = logging.getLogger(__name__)


class FortiSandboxAnalysisClient(object):

    def __init__(self, host, session=None, username=None,
                 password=None, log_level=None):
        self.session = session
        self.host = host + "/jsonrpc"
        self.username = username
        self.password = password
        self._sid = None
        log.setLevel(log_level if log_level else logging.INFO)

    def invalidate_session(self):
        self._sid = None

    @property
    def sid(self):
        while not(self._sid):
            log.info("Trying to get new session ID")
            response = api_fortisandbox.handle_request(
                host=self.host,
                session=self.session,
                params={
                    "data": [{"user": self.username,
                              "passwd": self.password}]},
                request_type="login")
            log.debug(response)
            log.debug(response.json())
            responsebody = response.json()
            log.debug("responsebody = %s", response.json())
            self._sid = responsebody.get('session', None)

        return self._sid

    def submit_file(self, resource_hash=None, stream=None):
        #log.info("submitfile hash = {0}".format(resource_hash))
        params = {}
        file_name = None
        if hasattr(stream, "name"):
            file_name = os.path.basename(stream.name)
        params['filename'] = b64encode(
            file_name.encode()).decode() if file_name else b64encode(resource_hash.encode()).decode()
        stream.seek(0)
        params['file'] = b64encode(stream.read()).decode()
        response = api_fortisandbox.handle_request(
            host=self.host,
            session=self.session,
            sid=self.sid,
            params=params,
            request_type='file_upload')
        log.debug("sub_file: response = %s" % response)
        log.debug("sub_file: response = %s" % response.json())
        return response

    def get_report(self, resource_hash=None, batch=None,hashtype="md5"):
        log.debug("get_report: resource_hash = %s" % resource_hash)
        params = {"ctype": hashtype, "url": "/scan/result/file",
                  "checksum": resource_hash.lower()}
        response = api_fortisandbox.handle_request(
            host=self.host,
            session=self.session,
            sid=self.sid,
            params=params,
            request_type="get_file_verdict")
        log.debug("get_report: response = %s" % str(response.json()))
        return response
