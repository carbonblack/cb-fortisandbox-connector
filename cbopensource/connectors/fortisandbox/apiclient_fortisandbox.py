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
                "data":[{"user": self.username,
                "passwd": self.password}]},
            	request_type="login")
		log.info(response)
		log.info(response.json())
		responsebody = response.json()
		result = responsebody.get(u'result',None)
		status = result.get(u'status',None) if result else None
		if result and status: 
		    self._sid = responsebody.get(u'session',None)
		    message = status.get(u"message")
		    code = status.get(u'code')
		    
		    if code == 0:
	return self._sid

    def submit_file(self, resource_hash=None, stream=None):
        log.info(
            "FortiSandbox Analysis: submit_file: hash = %s " %
            (resource_hash))
        params = {}
        '''
	"params": [
            {
                "file": "dGhpcyBpcyBhIHRlc3QhCg==",
                "filename": b64encode("test.txt"),
            }
        ],
	'''
        file_name = None
        if hasattr(stream, "name"):
            log.info("submitting file: fs.name: %s" % stream.name)
            file_name = os.path.basename(stream.name)
        params['filename'] = b64encode(file_name)
        params['file'] = b64encode(stream.read())
        response = api_fortisandbox.handle_request(
            host,
            session=self.session,
            sid=self.sid,
            params=params,
            request_type='file_upload')
        log.debug("sub_file: response = %s" % response)
        return response

    def get_report(self, resource_hash=None, batch=None):
        log.info("get_report: resource_hash = %s" % resource_hash)
        params = {"ctype": "md5","url":"/scan/results/file"}
        '''
	params": [
            {
                "sha256": "90877c1f6e7c97fb11249dc28dd16a3a3ddfac935d4f38c69307a71d96c8ef45",
		"ctype": "sha256"
            }
        ],
	'''
        if resource_hash:
            params["checksum"] = resource_hash
        else:
            raise Exception("No resources provided")
        response = api_fortisandbox.handle_request(
            host=self.host,
            session=self.session,
            sid=self.sid,
            params=params,
            request_type="get_file_verdict")
        return response
