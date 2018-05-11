#!/usr/bin/env python

import logging
import os
import api_fortisandbox
from base64 import b64encode, b64decode
log = logging.getLogger(__name__)


class FortiSandboxAnalysisClient(object):

    def __init__(self, host, session=None, username=None,
                 password=None, log_level=None):
        self.session = session
        self.host = host
        self.username = username
        self.password = password
        self._sid = None
        log.setLevel(log_level if log_level else logging.INFO)

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
            self._sid = responsebody.get(u'session', None)

        return self._sid

    def submit_file(self, resource_hash=None, stream=None):
        params = {}
        file_name = None
        if hasattr(stream, "name"):
            file_name = os.path.basename(stream.name)
        params['filename'] = b64encode(
            file_name) if file_name else b64encode(resource_hash)
        params['file'] = b64encode(stream.read())
        response = api_fortisandbox.handle_request(
            host=self.host,
            session=self.session,
            sid=self.sid,
            params=params,
            request_type='file_upload')
        log.debug("sub_file: response = %s" % str(response))
        return response

    def get_report(self, resource_hash=None, batch=None):
        log.debug("get_report: resource_hash = %s" % resource_hash)
        params = {"ctype": "md5", "url": "/scan/result/file",
                  "checksum": resource_hash.lower()}
        response = api_fortisandbox.handle_request(
            host=self.host,
            session=self.session,
            sid=self.sid,
            params=params,
            request_type="get_file_verdict")
        log.debug("get_report: response = %s" % str(response))
        return response
