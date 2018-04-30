from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress, AnalysisPermanentError)
from cbapi.connection import CbAPISessionAdapter
from apiclient_fortisandbox import (FortiSandboxAnalysisClient)
from datetime import (datetime, timedelta)

import cbint.utils.feed
import logging
from requests import Session

log = logging.getLogger(__name__)


class FortiSandboxProvider(BinaryAnalysisProvider):
    def __init__(self, name, username, password, host, log_level=None):
        super(FortiSandboxProvider, self).__init__(name)
        session = Session()
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        session.mount("https://", tls_adapter)
        self.fortisandbox_analysis = FortiSandboxAnalysisClient(
            host=host,
            username=username,
            password=password,
            session=session,
            log_level=log_level)

    def make_result(self, scan_id, result=None, md5=None):
        try:
            result = self.fortisandbox_analysis.get_report(
                scan_id) if not result else result
        except Exception as e:
            raise AnalysisTemporaryError(
                message="API error: %s" %
                str(e), retry_in=120)
        else:
            data = result.get('data', {})
            score = int(data.get('score', 0))
            if score == 0:
                return AnalysisResult(message="Benign", extended_message="",
                                      link=result['rating'],
                                      score=score)
            else:
                # 'rating' [] 'malware_name' [] vid []
                ratings = result.get("ratings", [])
                vids = result.get("vids", [])
                malware_names = result.get("malware_name", [])

                log.info("detected by = %s " % detected_by)
                report_string = "Fortisandbox Report:\n"
                link_start = "http://www.fortiguard.com/encyclopedia/virus/#id="
                for i in xrange(len(ratings)):
                    report_string += "{0} : {1} : {2} : {3}".format(
                        vids[i], ratings[i], malware_names[i], link_start + vids[i])

                malware_result = "[{0}] FortiSandbox report for {1}".format(
                    score, md5)
                return AnalysisResult(message=malware_result, extended_message=report_string,
                                      link=link_start + vids[0],
                                      score=score)

    def check_result_for(self, md5sum):
        try:
            response = self.fortisandbox_analysis.get_report(
                resource_hash=md5sum)
        except BaseException as be:
            log.debug(be)
            return None

        result = response.json().get("result", {})
	status = result.get("status")
        response_code = result.get("message", None)
        if (status is "OK"):
            return self.make_result(md5=md5sum, result=response)
        else:
            return AnalysisInProgress()

    def analyze_binary(self, md5sum, binary_file_stream):
        try:
            response = self.fortisandbox_analysis.submit_file(
                resource_hash=md5sum, stream=binary_file_stream)
        except BaseException as be:
            raise AnalysisTemporaryError(message=str(be), retry_in=15 * 60)

        result = response.get("result", {})
        response_code = result.get("status", {}).get("message", None)
        if response_code == "OK":
            log.info(
                "Submitted %s to fortisandbox for scanning succesfully" %
                resource_hash)
        else:
            raise AnalysisPermanentError(
                message="FortiSandbox analysis failed -> %s" %
                response_code, retry_in=120)

        response = self.fortisandbox_analysis.get_report(
            resource_hash=sha256sum)
        result = response.json().get("result", {})
        response_code = result.get("status", {}).get("message", None)
        if response_code == "OK":
            log.info(
                "Got analysis report from Fortisandbox for %s" %
                resource_hash)
        else:
            raise AnalysisTemporaryError(
                message="FortiSandbox analysis failed -> %s" %
                response_code, retry_in=120)

        return self.make_result(scan_id=scan_id, result=response)


class FortiSandboxConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string(
            "binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def integration_name(self):
        return 'Cb FortiSandbox Connector 1.0.0'

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("fortisandbox_quick_scan_threads", 2)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("fortisandbox_deep_scan_threads", 1)

    def get_provider(self):
        fortisandboxProvider = FortiSandboxProvider(name=self.name, password=self.fortisandbox_password, username=self.fortisandbox_username, host=self.fortisandbox_url,
                                                    log_level=self.log_level)

        return fortisandboxProvider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="FortiSandbox augments your security architecture by validating threats in a seperate, secure environment",
                                              tech_data="Fortisandbox appliance/virtual appliance and credentials are required to access this threat intelligence feed.  There are no requirements to share any data with Carbon Black to use this feed. However, binaries may be shared with fortisandbox.",
                                              provider_url="http://www.fortisandbox.com/",
                                              icon_path=None,
                                              display_name="FortiSandbox", category="Connectors")

    def validate_config(self):
        super(FortiSandboxConnector, self).validate_config()

        self.check_required_options(
            ["fortisandbox_username", "fortisandbox_url"])
        self.fortisandbox_password = self.get_config_string(
            "fortisandbox_password", "")
        self.fortisandbox_username = self.get_config_string(
            "fortisandbox_username", None)
        self.fortisandbox_url = self.get_config_string(
            "fortisandbox_url", None)
        self.log_level = logging.DEBUG if int(
            self.get_config_string(
                "debug", 0)) is 1 else logging.INFO
        log.setLevel(self.log_level)

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/fortisandbox"

    log = logging.getLogger()
    log.propogate = True
    log.setLevel(logging.DEBUG)
    config_path = os.path.join(my_path, "testing.conf")
    daemon = FortiSandboxConnector(name='fortisandboxtesting', configfile=config_path, work_directory=temp_directory,
                                   logfile=os.path.join(temp_directory, 'test.log'), debug=True)

    daemon.start()
