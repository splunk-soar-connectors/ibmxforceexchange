# File: test_whois.py
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

from xforce import xforce


def whois(self, param):
    xf = xforce("5c276816-8d76-4be2-99dc-ddfff748060c", "74afb990-7f63-402e-970b-02942489559a")
    whois_results = None

    try:
        whois_results = xf.get_whois(param["query_value"])
    except Exception as err:
        raise err

    if "xforce_whois" not in whois_results:
        raise Exception

    registrant = [contact for contact in whois_results["xforce_whois"]["contact"] if contact["type"] == "registrant"] or [{}]

    summary = {
        "registrar_name": whois_results["xforce_whois"].get("registrarName"),
        "admin_email": whois_results["xforce_whois"].get("contactEmail"),
        "created_date": whois_results["xforce_whois"].get("createdDate"),
        "expires_date": whois_results["xforce_whois"].get("expiresDate"),
        "registrant_name": registrant[0].get("name", ""),
        "registrant_organization": registrant[0].get("organization", ""),
        "registrant_country": registrant[0].get("country", ""),
    }
    print(f"summary: {summary}")

    raise Exception

    assert True
