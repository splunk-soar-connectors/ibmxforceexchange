from xforce import xforce


def whois(self, param):
    xf = xforce(
        '5c276816-8d76-4be2-99dc-ddfff748060c',
        '74afb990-7f63-402e-970b-02942489559a'
    )
    whois_results = None

    try:
        whois_results = xf.get_whois(param['query_value'])
    except Exception as err:
        raise err

    if 'xforce_whois' not in whois_results:
        raise Exception

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
    print('summary: %s' % summary)

    raise Exception

    assert True
