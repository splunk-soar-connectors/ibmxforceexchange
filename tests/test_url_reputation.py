# File: test_url_reputation.py
#
# Copyright (c) 2021-2025 Splunk Inc.
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

import datetime

from xforce import xforce


def cleanup_dict(results_dict, cleanup_keys, key_desc, value_desc):
    if len(cleanup_keys) > 0:
        cleanup_key = cleanup_keys[0]
        cleanup_keys.remove(cleanup_keys[0])
        if isinstance(results_dict.get(cleanup_key), dict):
            results_dict[cleanup_key] = cleanup_dict(results_dict[cleanup_key], list(cleanup_keys), key_desc, value_desc)
        elif isinstance(results_dict.get(cleanup_key), list):
            for idx, item in enumerate(results_dict.get(cleanup_key)):
                results_dict[cleanup_key][idx] = cleanup_dict(item, list(cleanup_keys), key_desc, value_desc)
        else:
            return results_dict
    else:
        if isinstance(results_dict, dict):
            return [{key_desc: key_field, value_desc: value_field} for key_field, value_field in results_dict.items()]
        elif isinstance(results_dict, list):
            return [{value_desc: value_field} for value_field in results_dict]
        else:
            return {value_desc: results_dict}
    return results_dict


def test_valid_url_reputation():
    xf = xforce("5c276816-8d76-4be2-99dc-ddfff748060c", "74afb990-7f63-402e-970b-02942489559a")

    url_report_results = None
    url_malware_results = None
    dns_results = None

    try:
        url_report_results = xf.get_url_report("www.pornhub.com")
    except Exception as err:
        raise err

    try:
        url_malware_results = xf.get_url_malware("www.pornhub.com")
    except Exception as err:
        raise err

    url_report_results.update(url_malware_results)

    try:
        dns_results = xf.get_dns("www.pornhub.com")
    except Exception as err:
        raise err

    url_report_results.update(dns_results)

    summary = {
        "score": (url_report_results["xforce_url_report"]["result"]["score"]),
        "category": ",".join([cat for cat in (url_report_results["xforce_url_report"]["result"]["categoryDescriptions"])]),
        "malware_observed": url_report_results["xforce_url_malware"].get("count", 0),
        "malware_in_last_90": 0
        if "error" in url_report_results["xforce_url_malware"]
        else len(
            [
                malware
                for malware in url_report_results["xforce_url_malware"]["malware"]
                if (datetime.date.today() - datetime.timedelta(days=90))
                <= datetime.datetime.strptime(malware["lastseen"], "%Y-%m-%dT%H:%M:%SZ").date()
            ]
        ),
    }
    print(f"summary: {summary}")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "result", "categoryDescriptions"], "category", "description")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "result", "cats"], "category", "is_cat")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "associated", "cats"], "category", "is_cat")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "associated", "categoryDescriptions"], "category", "description")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_malware", "malware", "family"], None, "name")

    url_report_results = cleanup_dict(url_report_results, ["xforce_dns", "A"], None, "record")

    url_report_results = cleanup_dict(url_report_results, ["xforce_dns", "AAAA"], None, "record")

    url_report_results = cleanup_dict(url_report_results, ["xforce_dns", "TXT"], None, "record")

    assert True


def test_invalid_url_reputation():
    xf = xforce("5c276816-8d76-4be2-99dc-ddfff748060c", "74afb990-7f63-402e-970b-02942489559a")

    url_report_results = None
    url_malware_results = None
    dns_results = None

    try:
        url_report_results = xf.get_url_report("www.pfdagdaornhub.com")
    except Exception as err:
        raise err

    try:
        url_malware_results = xf.get_url_malware("www.porgadgasdnhub.com")
    except Exception as err:
        raise err

    url_report_results.update(url_malware_results)

    try:
        dns_results = xf.get_dns("www.porgdagdanhub.com")
    except Exception as err:
        raise err

    url_report_results.update(dns_results)

    if url_report_results["xforce_url_report"].get("error") is not None:
        print("finish here")
        assert True
        return True

    summary = {
        "score": (url_report_results["xforce_url_report"]["result"]["score"]),
        "category": ",".join([cat for cat in (url_report_results["xforce_url_report"]["result"]["categoryDescriptions"])]),
        "malware_observed": url_report_results["xforce_url_malware"].get("count", 0),
        "malware_in_last_90": 0
        if "error" in url_report_results["xforce_url_malware"]
        else len(
            [
                malware
                for malware in url_report_results["xforce_url_malware"]["malware"]
                if (datetime.date.today() - datetime.timedelta(days=90))
                <= datetime.datetime.strptime(malware["lastseen"], "%Y-%m-%dT%H:%M:%SZ").date()
            ]
        ),
    }
    print(f"summary: {summary}")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "result", "categoryDescriptions"], "category", "description")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "result", "cats"], "category", "is_cat")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "associated", "cats"], "category", "is_cat")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_report", "associated", "categoryDescriptions"], "category", "description")

    url_report_results = cleanup_dict(url_report_results, ["xforce_url_malware", "malware", "family"], None, "name")

    url_report_results = cleanup_dict(url_report_results, ["xforce_dns", "A"], None, "record")

    url_report_results = cleanup_dict(url_report_results, ["xforce_dns", "AAAA"], None, "record")

    url_report_results = cleanup_dict(url_report_results, ["xforce_dns", "TXT"], None, "record")

    print(url_report_results)

    raise Exception

    assert True
