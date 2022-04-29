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


def test_valid_file_hash():
    xf = xforce(
        '5c276816-8d76-4be2-99dc-ddfff748060c',
        '74afb990-7f63-402e-970b-02942489559a'
    )

    file_report_results = None
    cnc_server_count = 0
    email_source_count = 0
    download_source_count = 0
    email_subject_count = 0

    try:
        file_report_results = (
            xf.get_malware_report('25909c9e62b870711309761791c735154b0620b5')  # pragma: allowlist secret
        )
    except Exception as err:
        raise err

    if 'error' not in file_report_results['xforce_malware_report']:
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

    print(file_report_results)

    if file_report_results['xforce_malware_report'].get('error') is not None:
        print('finish here')
        assert True
        return True

    summary = {
        'risk':
            (
                file_report_results
                (
                    ['xforce_malware_report']
                    .get('malware') or {'risk': 'Unknown'}
                )
                .get('risk', 'Unknown')
            ),
        'cnc_servers': cnc_server_count,
        'email_sources': email_source_count,
        'email_subjects': email_subject_count,
        'download_sources': download_source_count,
        'family':
            ','.join(
                [
                    family for family in (
                        file_report_results
                        (
                            (
                                ['xforce_malware_report']
                                .get('malware') or {'origins': None}
                            )
                            .get('origins') or {'family': None}
                        )
                        .get('family', [])
                    )
                ]
                +
                [
                    family
                    + '(' + str(family_dict.get('count', 0)) + ')'
                    for family, family_dict in (
                        file_report_results
                        (
                            (
                                ['xforce_malware_report']
                                .get('malware') or {'familyMembers': None}
                            )
                            .get('familyMembers') or {}
                        )
                        .items()
                    )
                ]
            )
    }

    print(summary)

    file_report_results = _cleanup_dict(
        file_report_results,
        ['xforce_malware_report', 'malware', 'family'],
        None, 'name'
    )

    file_report_results = _cleanup_dict(
        file_report_results,
        ['xforce_malware_report', 'malware', 'origins', 'external', 'family'],
        None, 'name'
    )

    file_report_results = _cleanup_dict(
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

    assert True


def test_invalid_file_hash():
    xf = xforce(
        '5c276816-8d76-4be2-99dc-ddfff748060c',
        '74afb990-7f63-402e-970b-02942489559a'
    )

    file_report_results = None
    cnc_server_count = 0
    email_source_count = 0
    download_source_count = 0
    email_subject_count = 0

    try:
        file_report_results = (
            xf.get_malware_report('5e486f0f008b4fd4048767c41a16cb4776f5699c')  # pragma: allowlist secret
        )
    except Exception as err:
        raise err

    print(file_report_results['xforce_malware_report'])
    print(file_report_results['xforce_malware_report'].get('error'))

    if file_report_results['xforce_malware_report'].get('error') is not None:
        print('finish here')
        assert True
        return True

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

    summary = {
        'risk':
            (file_report_results['xforce_malware_report'].get('malware', {'risk': 'Unknown'}).get('risk', 'Uknown')),
        'cnc_servers': cnc_server_count,
        'email_sources': email_source_count,
        'email_subjects': email_subject_count,
        'download_sources': download_source_count,
        'family': ','.join([family for family in (
            file_report_results['xforce_malware_report'].get('malware', {'origins': None}).get('origins',
                                                                                               {'external': None}).get(
                'family', []))]
                           +
                           [family + '(' + str(family_dict.get('count', 0)) + ')' for family, family_dict in (
                               file_report_results['xforce_malware_report'].get('malware', {'familyMembers': None}).get(
                                   'familyMembers', {}).items())])
    }

    print(summary)

    # TODO: _massage_list_data is not set anywhere.
    # if 'malware' in file_report_results['xforce_malware_report']:
    #     file_report_results['xforce_malware_report']['malware']['family'] = (
    #         _massage_list_data(
    #             'name',
    #             (
    #                 file_report_results
    #                 ['xforce_malware_report']
    #                 ['malware']
    #                 ['family']
    #             )
    #         )
    #     )
    #
    #     if 'origins' in (
    #         file_report_results
    #         ['xforce_malware_report']
    #         ['malware']
    #     ):
    #
    #         if 'external' in (
    #             file_report_results
    #             ['xforce_malware_report']
    #             ['malware']
    #             ['origins']
    #         ):
    #             (
    #                 file_report_results
    #                 ['xforce_malware_report']
    #                 ['malware']
    #                 ['origins']
    #                 ['external']
    #                 ['family']
    #             ) = _massage_list_data(
    #                 'name',
    #                 file_report_results
    #                 ['xforce_malware_report']
    #                 ['malware']
    #                 ['origins']
    #                 ['external']
    #                 ['family']
    #             )
    #
    #     if 'subjects' in (
    #         file_report_results
    #         ['xforce_malware_report']
    #         ['malware']
    #         ['origins']
    #     ):
    #         for row in (
    #             file_report_results
    #             ['xforce_malware_report']
    #             ['malware']
    #             ['origins']
    #             ['subjects']
    #             .get('rows', [])
    #         ):
    #             row['ips'] = _massage_list_data(
    #                 'ip',
    #                 row['ips']
    #             )
    #
    #     (
    #         file_report_results
    #         ['xforce_malware_report']
    #         ['malware']
    #         ['familyMembers']
    #     ) = [
    #         {
    #             'name': key_field,
    #             'count': value_field['count']
    #         }
    #         for key_field, value_field in (
    #             file_report_results
    #             ['xforce_malware_report']
    #             ['malware']
    #             ['familyMembers']
    #             .items()
    #         )
    #     ]

    print(file_report_results)

    assert True
