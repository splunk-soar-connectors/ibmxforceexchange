# --
# File: xforce_connector.py
#
# Copyright (c) AvantGarde Partners 2017
#
# This unpublished material is proprietary to Avantgarde Partners
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Avantgarde Partners.
#
# --

import datetime
import sys
from urllib.parse import urlparse

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from xforce import xforce


class XforceConnector(BaseConnector):

    def initialize(self):
        return phantom.APP_SUCCESS

    def finalize(self):
        return

    def handle_exception(self, exception_object):
        """All the code within BaseConnector::_handle_action is within a 'try:
        except:' clause. Thus if an exception occurs during the execution of
        this code it is caught at a single place. The resulting exception
        object is passed to the AppConnector::handle_exception() to do any
        cleanup of it's own if required. This exception is then added to the
        connector run result and passed back to spawn, which gets displayed
        in the Phantom UI.
        """

        return

    def handle_action(self, param):

        action_id = self.get_action_identifier()

        supported_actions = {
            'test connectivity': self._test_connectivity,
            'ip reputation': self.ip_reputation,
            'whois ip': self.whois,
            'whois domain': self.whois,
            'domain reputation': self.url_reputation,
            'url reputation': self.url_reputation,
            'file reputation': self.file_reputation
        }

        run_action = supported_actions[action_id]

        return run_action(param, action_id)

    def _initialize_xforce(self):
        config = self.get_config()
        xf = xforce(
            config.get('api-key'),
            config.get('api-password'),
            base_url=config.get('base_url'),
            verify_cert=config.get('')
        )
        return xf

    def _cleanup_dict(self, results_dict, cleanup_keys, key_desc, value_desc):
        if len(cleanup_keys) > 0:
            cleanup_key = cleanup_keys[0]
            cleanup_keys.remove(cleanup_keys[0])
            if isinstance(results_dict.get(cleanup_key), dict):
                results_dict[cleanup_key] = (
                    self._cleanup_dict(
                        results_dict[cleanup_key],
                        list(cleanup_keys),
                        key_desc, value_desc
                    )
                )
            elif isinstance(results_dict.get(cleanup_key), list):
                for idx, item in enumerate(results_dict.get(cleanup_key)):
                    results_dict[cleanup_key][idx] = self._cleanup_dict(
                        item,
                        list(cleanup_keys),
                        key_desc, value_desc
                    )
            else:
                return results_dict
        else:
            if isinstance(results_dict, dict):
                return [
                    {key_desc: key_field, value_desc: value_field}
                    for key_field, value_field
                    in results_dict.items()
                ]
            elif isinstance(results_dict, list):
                return [
                    {value_desc: value_field}
                    for value_field
                    in results_dict
                ]
            else:
                return {value_desc: results_dict}
        return results_dict

    def _test_connectivity(self, param, action_id):
        xf = self._initialize_xforce()

        try:
            # if for some reason google doesn't exist this should still
            # work, as long as x_force is rechable. Report will just
            # have no info in it.
            dns_report = xf.get_dns('google.com')
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                'Error connecting to IBM X_Force. Details:' + err.message
            )
        else:
            if 'xforce_dns' not in dns_report:
                return self.set_status_save_progress(
                    phantom.APP_ERROR,
                    'Error connecting to IBM X_Force. Details: Unexpected data in X_Force DNS report _ ' + str(
                        dns_report)
                )
            else:
                return self.set_status_save_progress(
                    phantom.APP_SUCCESS,
                    'Successfully connected to IBM X_Force API.'
                )

    def whois(self, param, action_id):
        xf = self._initialize_xforce()
        whois_results = None
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            whois_results = xf.get_whois(param['query_value'])
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                'Error running IBM X_Force WHOIS. Details:' + err.message
            )

        registrant = [
            contact for contact
            in whois_results['xforce_whois']['contact']
            if contact['type'] == 'registrant'
        ] or [{}]

        summary = {
            'registrar_name':
                whois_results['xforce_whois'].get('registrarName'),
            'admin_email':
                whois_results['xforce_whois'].get('contactEmail'),
            'created_date':
                whois_results['xforce_whois'].get('createdDate'),
            'expires_date':
                whois_results['xforce_whois'].get('expiresDate'),
            'registrant_name':
                registrant[0].get('name', ''),
            'registrant_organization':
                registrant[0].get('organization', ''),
            'registrant_country':
                registrant[0].get('country', '')
        }

        action_result.update_summary(summary)
        action_result.add_data(whois_results)
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def ip_reputation(self, param, action_id):
        xf = self._initialize_xforce()
        ip_report_results = None
        ip_malware_results = None
        dns_results = None

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            ip_report_results = xf.get_ip_report(param['ip'])
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                'Error running IBM X_Force IP Report. Details:' + err.message
            )

        try:
            ip_malware_results = xf.get_ip_malware(param['ip'])
        except Exception as err:
            return self.set_status_save_progress(phantom.APP_ERROR,
                                                 'Error running IBM X_Force IP Malware report. Details: ' + err.message)

        ip_report_results.update(ip_malware_results)

        try:
            dns_results = xf.get_dns(param['ip'])
        except Exception as err:
            return self.set_status_save_progress(phantom.APP_ERROR,
                                                 'Error running IBM X_Force DNS report. Details: ' + err.message)

        ip_report_results.update(dns_results)

        summary = {'score': (ip_report_results['xforce_ip_report']['score']),
                   'reason': (ip_report_results['xforce_ip_report']['reasonDescription']),
                   'category': ', '.join(
                       [cat + '(' + str(ip_report_results['xforce_ip_report']['cats'][cat]) + ')' for cat in
                        (ip_report_results['xforce_ip_report']['categoryDescriptions'])]),
                   'country': (ip_report_results['xforce_ip_report']['geo']['country']),
                   'earliest_entry': (ip_report_results['xforce_ip_report']['history'][0]['created']),
                   'latest_entry': (ip_report_results['xforce_ip_report']['history'][
                       len(ip_report_results['xforce_ip_report']['history']) - 1]['created']),
                   'subnets': ','.join(
                       [subnet['subnet'] for subnet in (ip_report_results['xforce_ip_report']['subnets'])]),
                   'malware_observed': len(ip_report_results['xforce_ip_malware'].get('malware') or []),
                   'malware_last_90': 0 if 'error' in ip_report_results['xforce_ip_malware'] else len(
                       [malware for malware in ip_report_results['xforce_ip_malware']['malware'] if
                        (datetime.date.today() - datetime.timedelta(days=-100000)) <= datetime.datetime.strptime(
                            malware['lastseen'], '%Y-%m-%dT%H:%M:%SZ').date()])
                   }

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_ip_report', 'history', 'categoryDescriptions'],
            'category', 'description'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_ip_report', 'history', 'cats'],
            'category', 'percentage'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_ip_report', 'categoryDescriptions'],
            'category', 'description'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_ip_report', 'cats'],
            'category', 'percentage'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_ip_report', 'subnets', 'categoryDescriptions'],
            'category', 'description'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_ip_malware', 'malware', 'family'],
            None, 'name'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_dns', 'A'],
            None, 'record'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_dns', 'AAAA'],
            None, 'record'
        )

        ip_report_results = self._cleanup_dict(
            ip_report_results,
            ['xforce_dns', 'TXT'],
            None, 'record'
        )

        action_result.update_summary(summary)
        action_result.add_data(ip_report_results)
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def url_reputation(self, param, action_id):
        xf = self._initialize_xforce()
        url_report_results = None
        url_malware_results = None
        dns_results = None

        if action_id == 'domain reputation':
            param['query_value'] = (
                urlparse(param['query_value']).netloc or param['query_value']
            )

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            url_report_results = xf.get_url_report(param['query_value'])
        except Exception as err:
            return self.set_status_save_progress(phantom.APP_ERROR,
                                                 'Error running IBM X_Force url Report. Details:' + err.message)

        if url_report_results['xforce_url_report'].get('error') is not None:
            summary = {
                'score': 'Unkown',
                'category': 'Unknown',
                'malware_observed': 0,
                'malware_in_last_90': 0,
            }

            action_result.update_summary(summary)

            return (action_result.set_status(phantom.APP_SUCCESS, 'No data found.'))

        try:
            url_malware_results = xf.get_url_malware(param['query_value'])
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                'Error running IBM X_Force url Malware report. Details: ' + err.message)

        url_report_results.update(url_malware_results)

        try:
            dns_results = xf.get_dns(param['query_value'])
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                'Error running IBM X_Force DNS report. Details: ' + err.message)

        url_report_results.update(dns_results)

        summary = {'score': (url_report_results['xforce_url_report']['result']['score']),
                   'category': ','.join(
                       [cat for cat in (url_report_results['xforce_url_report']['result']['categoryDescriptions'])]),
                   'malware_observed': url_report_results['xforce_url_malware'].get('count', 0),
                   'malware_in_last_90': 0 if 'error' in url_report_results['xforce_url_malware'] else len(
                       [malware for malware in url_report_results['xforce_url_malware']['malware'] if
                        (datetime.date.today() - datetime.timedelta(days=90)) <= datetime.datetime.strptime(
                            malware['lastseen'], '%Y-%m-%dT%H:%M:%SZ').date()])
                   }

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_url_report', 'result', 'categoryDescriptions'],
            'category', 'description'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_url_report', 'result', 'cats'],
            'category', 'is_cat'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_url_report', 'associated', 'cats'],
            'category', 'is_cat'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_url_report', 'associated', 'categoryDescriptions'],
            'category', 'description'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_url_malware', 'malware', 'family'],
            None, 'name'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_dns', 'A'],
            None, 'record'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_dns', 'AAAA'],
            None, 'record'
        )

        url_report_results = self._cleanup_dict(
            url_report_results,
            ['xforce_dns', 'TXT'],
            None, 'record'
        )

        action_result.update_summary(summary)
        action_result.add_data(url_report_results)
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def file_reputation(self, param, action_id):

        xf = self._initialize_xforce()
        file_report_results = None
        cnc_server_count = 0
        email_source_count = 0
        download_source_count = 0
        email_subject_count = 0
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            file_report_results = xf.get_malware_report(param['hash'])
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                'Error running IBM X_Force file report. Details:' + err.message
            )

        if file_report_results['xforce_malware_report'].get('error') is not None:
            summary = {
                'risk': 'Unkown',
                'cnc_servers': 0,
                'email_sources': 0,
                'email_subjects': 0,
                'download_source': 0,
                'family': 'Unknown'
            }

            action_result.update_summary(summary)

            return (
                action_result.set_status(
                    phantom.APP_SUCCESS,
                    'No data found.'
                )
            )

        cnc_server_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['CnCServers']
                .get('rows', [])
            )
        )

        email_source_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['emails']
                .get('rows', [])
            )
        )

        download_source_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['downloadServers']
                .get('rows', [])
            )
        )

        email_subject_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['subjects']
                .get('rows', [])
            )
        )

        cnc_server_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['CnCServers']
                .get('rows', [])
            )
        )

        email_source_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['emails']
                .get('rows', [])
            )
        )

        download_source_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['downloadServers']
                .get('rows', [])
            )
        )

        email_subject_count = (
            len(
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['origins']
                ['subjects']
                .get('rows', [])
            )
        )
        family_reports = [family for family in (((file_report_results['xforce_malware_report'].get('malware') or {
            'origins': None}).get('origins') or {'family': None}).get('family', []))]
        family_dicts = [family + '(' + str(family_dict.get('count', 0)) + ')' for family, family_dict in (
            (file_report_results['xforce_malware_report'].get('malware') or {'familyMembers': None}).get(
                'familyMembers', {}).items())]
        summary = {
            'risk': ((file_report_results['xforce_malware_report'].get('malware') or {'risk': 'Unknown'}).get('risk',
                                                                                                              'Unknown')),
            'cnc_servers': cnc_server_count,
            'email_sources': email_source_count,
            'email_subjects': email_subject_count,
            'download_sources': download_source_count,
            'family': ','.join(family_reports + family_dicts)
        }

        file_report_results = self._cleanup_dict(
            file_report_results,
            ['xforce_malware_report', 'malware', 'family'],
            None, 'name'
        )

        file_report_results = self._cleanup_dict(
            file_report_results,
            ['xforce_malware_report', 'malware', 'origins', 'external', 'family'],
            None, 'name'
        )

        file_report_results = self._cleanup_dict(
            file_report_results,
            ['xforce_malware_report', 'malware', 'origins', 'subjects', 'rows', 'ips'],
            None, 'ip'
        )

        (
            file_report_results
            ['xforce_malware_report']
            ['malware']
            ['familyMembers']
        ) = [
            {
                'name': key_field,
                'count': value_field['count']
            }
            for key_field, value_field in (
                file_report_results
                ['xforce_malware_report']
                ['malware']
                ['familyMembers']
                .items()
            )
        ]

        action_result.update_summary(summary)
        action_result.add_data(file_report_results)
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()


if __name__ == '__main__':

    import json
    # import pudb
    from traceback import format_exc

    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print('No test json specified as input')
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = XforceConnector()
        connector.print_progress_message = True
        try:
            ret_val = connector.handle_action(json.dumps(in_json))
        except:
            print(format_exc())
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
