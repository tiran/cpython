# Convenience test module to run all of the XML-related tests in the
# standard library.

import sys
import subprocess


TESTS = [
    'test_minidom', 'test_pyexpat', 'test_sax', 'test_xml_dom_minicompat',
    'test_xml_etree', 'test_xml_etree_c', 'test_xmlrpc',
]


def run_regrtests(*extra_args):
    args = [
        sys.executable,
        '-Werror', '-bb',  # turn warnings into exceptions
        '-m', 'test',
    ]
    if not extra_args:
        args.extend([
            '-r', '-w', '-u', 'network', '-j', '0'
        ])
    else:
        args.extend(extra_args)
    args.extend(TESTS)
    result = subprocess.call(args)
    sys.exit(result)


if __name__ == '__main__':
    run_regrtests(*sys.argv[1:])
