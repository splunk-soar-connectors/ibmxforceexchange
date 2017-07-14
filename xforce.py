# --
# File: xforce.py
#
# Copyright (c) Avantgarde Partners, 2017
#
# This unpublished material is proprietary to Avantgarde Partners
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Avantgarde Partners.
#
# --

import base64
import requests


class xforce(object):

    def __init__(
        self,
        api_key,
        api_password,
        base_url='https://api.xforce.ibmcloud.com',
        verify_cert=False
    ):
        self.base_url = base_url
        self.api_key = api_key
        self.api_password = api_password
        self.auth_token = api_key + ':' + api_password
        self.header = {
            'Authorization': (
                'Basic '
                + base64.b64encode(self.auth_token.encode('utf-8'))
                .decode('utf-8')
            )
        }
        self.verify_cert = verify_cert

    def _send_request(self, url, method, payload=None, content_type=None):
        url = self.base_url + url
        request_func = getattr(requests, method)

        if request_func is None:
            raise ValueError('Incorrect requests action specified')

        try:
            r = request_func(
                url,
                headers=self.header,
                data=payload,
                verify=self.verify_cert
            )

            r.raise_for_status
        except requests.exceptions.SSLError as err:
            raise Exception(
                'Error connecting to API - '
                'Likely due to the "validate server certificate" option. '
                'Details: ' + str(err)
            )
        except requests.exceptions.HTTPError as err:
            raise Exception(
                'Error calling - ' + url + ' - \n'
                'HTTP Status: ' + r.status
                + 'Reason: ' + r.reason
                + 'Details: ' + str(err)
            )
        except requests.exceptions.RequestException as err:
            raise Exception(
                'Error calling - ' + url + ' - Details: ' + str(err)
            )

        try:
            results = r.json()
        except ValueError:
            results = r.text

        return results

    def get_dns(self, query_value):
        response = self._send_request('/resolve/' + query_value, 'get')
        json_response = {'xforce_dns': response}

        return json_response

    def get_ip_report(self, ip):
        response = self._send_request('/ipr/' + ip, 'get')
        json_response = {'xforce_ip_report': response}

        return json_response

    def get_ip_reputation(self, ip):
        response = self._send_request('/ipr/history/' + ip, 'get')
        json_response = {'xforce_ip_reputation': response}

        return json_response

    def get_ip_malware(self, ip):
        response = self._send_request('/ipr/malware/' + ip, 'get')
        json_response = {'xforce_ip_malware': response}

        return json_response

    def get_malware_report(self, file_hash):
        response = self._send_request('/malware/' + file_hash, 'get')
        json_response = {'xforce_malware_report': response}

        return json_response

    def get_malware_family(self, family):
        response = self._send_request('/malware/family/' + family, 'get')
        json_response = {'xforce_malware_family': response}

        return json_response

    def get_url_report(self, url):
        response = self._send_request('/url/' + url, 'get')
        json_response = {'xforce_url_report': response}

        return json_response

    def get_url_malware(self, url):
        response = self._send_request('/url/malware/' + url, 'get')
        json_response = {'xforce_url_malware': response}

        return json_response

    def get_whois(self, query_data):
        response = self._send_request('/whois/' + query_data, 'get')
        json_response = {'xforce_whois': response}

        return json_response
