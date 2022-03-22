import os
import requests
import json
from base64 import b64encode, b64decode
# NOTE: For 'requests' to work with 'https' addrs, must use 'verify=False'
# to ignore invalid SSL certificates.
TEST_URL = 'https://10.210.39.16/jsonrpc'
# NOTE: List is used to control the order in which RPC requests are sent (order
# matters).
TEST_LIST = [
    'get_status',
    'get_dev_settings',
    'get_option_settings',
    'get_scan_stats',
    'get_backup_file',
    'get_file_verdict',
    'get_file_rating',
    'file_upload',
    'file_upload_url',
    'get_url_rating',
    'get_job_verdict',
    'cancel-submssion',
    'get-jobs-of-submission',
    'get-job-behavior'
]
# 'set_dev_settings'
# 'set_option_settings'
# NOTE: 'session' values will be set after login in test function below.
TEST_INPUTS = {
    'login': {
        "method": "exec",
        "params": [
            {
                "url": "/sys/login/user",
                "data": [{"user": "admin", "passwd": ""}]
            }
        ],
        "id": 1,
        "ver": "2.1"
    },
    'logout': {
        "method": "exec",
        "params": [{"url": "/sys/logout", }],
        "session": '',
        "id": 2,
        "ver": "2.1"
    },
    'get_status': {
        "method": "get",
        "params": [{"url": "/sys/status", }],
        "session": '',
        "id": 3,
        "ver": "2.1"
    },
    'get_dev_settings': {
        "method": "get",
        "params": [{"url": "/config/scan/devsniffer", }],
        "session": '',
        "id": 4,
        "ver": "2.1"
    },
    'get_option_settings': {
        "method": "get",
        "params": [{
            "url": "/config/scan/options",
            "data": [
                {
                    "cloud_upload": 0,
                    "vm_network_access": 1,
                    "log_device_submission": 1,
                    "rej_dup_device_submission": 1,
                    "del_clean_file": 20160,
                    "del_job_info": 20160
                }
            ]
        }
        ],
        "session": '',
        "id": 7,
        "ver": "2.1"
    },
    'get_scan_stats': {
        "method": "get",
        "params": [
            {
                "url": "/scan/stat/last_7day",
            }
        ],
        "session": '',
        "id": 8,
        "ver": "2.1"
    },
    'get_backup_file': {
        "method": "exec",
        "params": [{"url": "/backup/config", }],
        "session": '',
        "id": 9,
        "ver": "2.1"
    },
    'get_file_verdict_old': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/file",
                "md5": "90877c1f6e7c97fb11249dc28dd16a3a3ddfac935d4f38c69307a71d96c8ef45"
            }
        ],
        "session": '',
        "id": 10,
        "ver": "2.1"
    },
    'get_file_verdict': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/file",
                "checksum": None,
                "ctype": "md5"
            }
        ],
        "session": '',
        "id": 10,
        "ver": "2.1"
    },
    'get_job_verdict': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/job",
                "jid": 1986798562984719030
            }
        ],
        "session": '',
        "id": 10,
        "ver": "2.1"
    },
    'get_file_rating': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/filerating",

                "sha256": "90877c1f6e7c97fb11249dc28dd16a3a3ddfac935d4f38c69307a71d96c8ef45"
            }
        ],
        "session": '',
        "id": 13,
        "ver": "2.1"
    },
    'file_upload': {
        "method": "set",
        "params": [
            {
                "file": "",
                "filename": "",
                "url": "/alert/ondemand/submit-file",
                "type": "file"
            }
        ],
        "session": '',
        "id": 11,
        "ver": "2.1"
    },
    'file_upload_url': {
        "method": "set",
        "params": [
            {
                "file": "dGhpcyBpcyBhIHRlc3QhCg==",
                "filename": b64encode("test.txt"),
                "url": "/alert/ondemand/submit-file",
                "timeout": "60",
                "depth": "1",
                "type": "url"
            }
        ],
        "session": '',
        "id": 12,
        "ver": "2.1"
    },
    'get_url_rating': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/urlrating",
                "address": "1385967878564516.172.16.92.92.0"
            }
        ],
        "session": '',
        "id": 14,
        "ver": "2.1"
    },
    'cancel-submssion': {
        "method": "exec",
        "params": [
            {
                "url": "/alert/ondemand/cancel-submssion",
                "sid": 2030159349466600881,
                "reason": 'want to cancel'
            }
        ],
        "session": "",
        "id": 16,
        "ver": "2.1"
    },
    'get-jobs-of-submission': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/get-jobs-of-submission",
                "sid": 2050809724026386707,
            }
        ],
        "session": "",
        "id": 17,
        "ver": "2.1"
    },
    'get-job-behavior': {
        "method": "get",
        "params": [
            {
                "url": "/scan/result/get-job-behavior",

                "sha256": "4e811adc363f4f52b9b4268d789aae5094056c8f5771fbf3f049185737ea51a5"
            }
        ],
        "session": "gzKj2PsMZ+4Hhs8Q9Ra+br+YStvpqWz\/8e291G1j1GI=",
        "id": 18,
        "ver": "2.1"
    }
}


def _handle_post(post_url, data):
    """
    POST JSON RPC request..
    @type post_url: basestring
    @param post_url: URL to server running RPC code.
    @type data: dict
    @param data: JSON RPC request data.
    @rtype: HttpResponse
    @return: JSON RPC response data.
    """
    response = requests.post(post_url, data=json.dumps(data), verify=False)
    return response


def _handle_post_with_session(session, post_url, data):
    """
    POST JSON RPC request..
    @type post_url: basestring
    @param post_url: URL to server running RPC code.
    @type data: dict
    @param data: JSON RPC request data.
    @rtype: HttpResponse
    @return: JSON RPC response data.
    """
    response = session.post(post_url, data=json.dumps(data), verify=False)
    return response


def _load_file_for_upload(path_to_file, test_input, filename=''):
    """
    Load file contents into input mapping.
    @type path_to_file: basestring
    @param path_to_file: files absolute path.
    @type test_input: dict
    @param test_input: JSON RPC request data.
    @type filename: basestring
    @param filename: filename override optional param.
    @rtype: dict
    @return: updated JSON RPC request dict.
    """
    f = open(path_to_file, 'rb')
    data = f.read()
    f.close()
    filename = os.path.basename(path_to_file) if not filename else filename
    test_input['params'][0]['file'] = b64encode(data)
    test_input['params'][0]['filename'] = b64encode(filename)
    return test_input


def handle_request(host, sid=None, session=None,
                   params=None, request_type=None, filepath=None):
    test_input = TEST_INPUTS.get(request_type, None)
    #print test_input
    if sid:
        test_input['session'] = sid
    for key, value in list(params.items()):
        #print ("k, v = %s , %s " % (key, value))
        test_input['params'][0][key] = value
    #print test_input['params'][0]
    response = _handle_post_with_session(session, host, test_input)
    return response


def main():
    """:wq!
    Test RPC supported requests.
    @rtype: None
    @return: None
    """
    # NOTE: login, create session ID (sid).
    login_input = TEST_INPUTS.get('login')
    login_response = _handle_post(TEST_URL, login_input)
    result = json.loads(login_response.text)['result']
    sid = json.loads(login_response.text)['session']
    print(login_response.text)
    # NOTE: 'OVERRIDE_FILE' should be the absolute path to the file.
    # When submitting a file via RPC the noted file ('OVERRIDE_FILE')
    # will be used as an OVERRIDE. This can be used to send files
    # from your local PC to an FSA device.
    OVERRIDE_FILE = ''
    for test_key in TEST_LIST:
        print('test key = %s' % test_key)
        test_input = TEST_INPUTS.get(test_key)
        print('test_input = %s' % test_input)
        test_input['session'] = sid
    # NOTE: Skip url file upload IF path to file is not defined.
        if test_key == 'file_upload_url' and not OVERRIDE_FILE:
            continue
        test_input = _load_file_for_upload(OVERRIDE_FILE, test_input) \
            if OVERRIDE_FILE and test_key in ['file_upload', 'file_upload_url'] \
            else test_input
    response = _handle_post(TEST_URL, test_input)
    print(response)
    if test_key == 'get_backup_file':
        #print json.loads(response.text)['result']['data']['file']
        print(b64decode(json.loads(response.text)['result']['data']['file']))
    elif test_key == 'get-job-behavior':
        result = json.loads(response.text)['result']
        if 'data' in result and 'behavior_files' in result['data']:
            with open("/tmp/json_behavior.tgz", 'wb') as output:
                output.write(b64decode(result['data']['behavior_files']))
        else:
            print("No behavior data was found")
    else:
        print(response.text)
    # NOTE: Logout of session
    logout_input = TEST_INPUTS.get('logout')
    logout_input['session'] = sid
    logout_response = _handle_post(TEST_URL, logout_input)
    print(logout_response.text)


if __name__ == "__main__":
    main()
