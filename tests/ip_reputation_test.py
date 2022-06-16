# File: ip_reputation_test.py
#
# Copyright (c) 2021-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from xforce import xforce


def _cleanup_dict(results_dict, cleanup_keys, key_desc, value_desc):
    if len(cleanup_keys) > 0:
        cleanup_key = cleanup_keys[0]
        cleanup_keys.remove(cleanup_keys[0])
        if isinstance(results_dict.get(cleanup_key), dict):
            results_dict[cleanup_key] = (
                _cleanup_dict(
                    results_dict[cleanup_key],
                    list(cleanup_keys),
                    key_desc, value_desc
                )
            )
        elif isinstance(results_dict.get(cleanup_key), list):
            for idx, item in enumerate(results_dict.get(cleanup_key)):
                results_dict[cleanup_key][idx] = _cleanup_dict(
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


def test_ip_reputation():
    xf = xforce(
        '5c276816-8d76-4be2-99dc-ddfff748060c',
        '74afb990-7f63-402e-970b-02942489559a'
    )

    try:
        ip_report_results = xf.get_ip_report('190.104.178.46')
    except Exception as err:
        raise err

    try:
        ip_malware_results = xf.get_ip_malware('190.104.178.46')
    except Exception as err:
        raise err

    ip_report_results.update(ip_malware_results)

    try:
        dns_results = xf.get_dns('190.104.178.46')
    except Exception as err:
        raise err

    ip_report_results.update(dns_results)

    # TODO: _100000 is not set anywhere.
    # summary = {
    #     'score':
    #         (
    #             ip_report_results
    #             ['xforce_ip_report']
    #             ['score']
    #         ),
    #     'reason':
    #         (
    #             ip_report_results
    #             ['xforce_ip_report']
    #             ['reasonDescription']
    #         ),
    #     'category':
    #         ', '.join([
    #             cat + '('
    #             + str(
    #                 ip_report_results
    #                 ['xforce_ip_report']
    #                 ['cats']
    #                 [cat]
    #             )
    #             + ')'
    #             for cat
    #             in (
    #                 ip_report_results
    #                 ['xforce_ip_report']
    #                 ['categoryDescriptions']
    #             )
    #         ]),
    #     'country':
    #         (
    #             ip_report_results
    #             ['xforce_ip_report']
    #             ['geo']
    #             ['country']
    #         ),
    #     'earliest_entry':
    #         (
    #             ip_report_results
    #             ['xforce_ip_report']
    #             ['history']
    #             [0]
    #             ['created']
    #         ),
    #     'latest_entry':
    #         (
    #             ip_report_results
    #             ['xforce_ip_report']
    #             ['history']
    #             [
    #                 len(
    #                     ip_report_results
    #                     ['xforce_ip_report']
    #                     ['history']
    #                 ) - 1
    #                 ]
    #             ['created']
    #         ),
    #     'subnets':
    #         ','.join([
    #             subnet['subnet'] for subnet in (
    #                 ip_report_results
    #                 ['xforce_ip_report']
    #                 ['subnets']
    #             )
    #         ]),
    #     'malware_observed':
    #         len(
    #             ip_report_results['xforce_ip_malware'].get('malware')
    #             or []
    #         ),
    #     'malware_last_90':
    #         0 if 'error' in ip_report_results['xforce_ip_malware']
    #         else
    #         len([
    #             malware for malware in ip_report_results['xforce_ip_malware']['malware'] if
    #             (datetime.date.today() - datetime.timedelta(days=_100000)) <= datetime.datetime.strptime(
    #                 malware['lastseen'], '%Y-%m-%dT%H:%M:%SZ').date()
    #         ])
    #
    # }
    # print('summary: %s' % summary)

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_ip_report', 'history', 'categoryDescriptions'],
        'category', 'description'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_ip_report', 'history', 'cats'],
        'category', 'percentage'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_ip_report', 'categoryDescriptions'],
        'category', 'description'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_ip_report', 'subnets', 'categoryDescriptions'],
        'category', 'description'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_ip_malware', 'malware', 'family'],
        None, 'name'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_dns', 'A'],
        None, 'record'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_dns', 'AAAA'],
        None, 'record'
    )

    ip_report_results = _cleanup_dict(
        ip_report_results,
        ['xforce_dns', 'TXT'],
        None, 'record'
    )

    print(ip_report_results)

    raise Exception

    assert True
