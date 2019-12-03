#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# vulners-lookup
# --------------
# Perform vulnerabilities lookup on Vulners, the largest database (lots of sources including
# exploit-db, 0day.today, Nessus, OpenVAS...). Ref: https://vulners.com/stats
#
# Based on Vulners API (https://github.com/vulnersCom/api)
#
import argparse
import requests
import vulners
import pprint
import colored
import prettytable
import textwrap
import sys


# Utils functions
# -----------------------------------------------------------------------------
def colorize(string, color=None, highlight=None, attrs=None):
    """Apply style on a string"""
    # Colors list: https://pypi.org/project/colored/
    return colored.stylize(string, (colored.fg(color) if color else '') + \
                                   (colored.bg(highlight) if highlight else '') + \
                                   (colored.attr(attrs) if attrs else ''))

def remove_non_printable_chars(string):
    """Remove non-ASCII chars like chinese chars"""
    printable = set("""0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ """)
    return ''.join(filter(lambda x: x in printable, string))

def table(columns, data, hrules=True):
    """Print a table"""
    columns = map(lambda x:colorize(x, attrs='bold'), columns)
    table = prettytable.PrettyTable(hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=columns)
    for row in data:
        table.add_row(row)
    table.align = 'l'
    print(table)

def shorten(string, maxlength):
    """Shorten a string if it exceeds a given length"""
    if len(string) <= maxlength:
        return string
    else:
        return textwrap.wrap(string, maxlength)[0]+'...'

def get_cvss_score(vuln, vulners_api):
    """Get CVSS score if available, otherwise get Vulners AI score"""
    cvss = vuln['cvss']['score']

    if cvss == 0.0:
        try:
            return vulners_api.aiScore(vuln['description'])[0]
        except:
            return 0.0
    else:
        return cvss

def color_cvss(cvss):
    """Attribute a color to the CVSS score"""
    try:
        cvss = float(cvss)
    except:
        return None

    if cvss < 3:
        color = 'green_3b'
    elif cvss <= 5:
        color = 'yellow_1'
    elif cvss <= 7:
        color = 'orange_1'
    elif cvss <= 8.5:
        color = 'dark_orange'
    else:
        color = 'red'
    return color

def info(string):
    """Print info string"""
    print('{}{}'.format(colorize('[*] ', color='light_blue', attrs='bold'), string))


def warning(string):
    """Print warning string"""
    print('{}{}'.format(colorize('[!] ', color='orange_1', attrs='bold'), string))


def error(string):
    """Print error string"""
    print('{}{}'.format(colorize('[!] ', color='red', attrs='bold'), string))




def global_search(apikey, query):
    info('Looking for "{}" in whole Vulners database...'.format(query))

    try:
        vulners_api = vulners.Vulners(api_key=apikey)
    except:
        error('Unable to connect to Vulners.com. Check internet connection !')
        sys.exit(1)

    try:
        results = vulners_api.search('{}  order:published'.format(query), limit=200)
    except Exception as e:
        error('Unable to get results. Might happen is maximum requests count has been ' \
            'reached with the API key in use')
        sys.exit(1)

    nb_results = 0
    for r in results:
        if r['bulletinFamily'] not in ('info', 'blog', 'bugbounty', 'tools', 'advertisement'):
            nb_results += 1

    if nb_results == 0:
        warning('No result has been found !')
        sys.exit(0)
    else:
        info('{} results found. Retrieving CVSS scores or computing AI scores if not available...'.format(nb_results))


    columns = [
        '#',
        'Score',
        'Title',
        'Description',
        'URL',
        'Type',
    ]
    data = list()
    i = 1
    for r in results:
        if r['bulletinFamily'] not in ('info', 'blog', 'bugbounty', 'tools', 'advertisement'):
            score = get_cvss_score(r, vulners_api)
            type_ = r['bulletinFamily']
            if type_ == 'exploit':
                type_ = colorize(type_, color='red', attrs='bold')
            data.append([
                #textwrap.fill(r['id'], 14),
                i,
                colorize(score, color=color_cvss(score), attrs='bold'),
                textwrap.fill('[{id}] {title}'.format(id=r['id'], title=remove_non_printable_chars(r['title'])), 30),
                textwrap.fill(shorten(remove_non_printable_chars(r['description']), 230), 50),
                textwrap.fill(r['vhref'],78),
                type_,
            ])
            i += 1

    #pprint.pprint(results)

    info('Results ordered by published date (desc):')
    table(columns, data, hrules=True)


def software_api(name, version):
    info('Querying Vulners API for: name="{name}", version={version}...'.format(name=name, version=version))

    try:
        res = requests.get('https://vulners.com/api/v3/burp/software',
            params={'software': name, 'version': version, 'type': 'software'})
    except:
        error('Unable to query the Vulners API. Check Internet Connection !')
        sys.exit(1)

    if not res:
        error('Empty result returned by Vulners API')
        sys.exit(1)

    try:
        json = res.json()
    except:
        error('Response from Vulners endpoint is not valid JSON data. Cannot process it !')
        sys.exit(1)


    # Empty result :
    # {
    #   "result": "warning",
    #   "data": {
    #     "warning": "Nothing found for Burpsuite search request",
    #     "errorCode": 401
    #   }
    # }
    results = []
    if json['result'] == 'OK':
        for res in json['data']['search']:
            result = {
                'reference': res['_id'],
                'score': res['_source']['cvss']['score'] if 'cvss' in res['_source'] \
                    and 'score' in res['_source']['cvss'] else None,
                'title': res['_source']['title'],
                'description': res['_source']['description'],
                'url': res['_source']['href'],
                'type': res['_source']['type']
            }
            if result['score'] == 0.0:
                result['score'] = None

            results.append(result)

    else:
        warning('Vulners API returns 0 result')
        sys.exit(0)


    columns = [
        '#',
        'Score',
        'Title',
        'Description',
        'URL',
        'Type',
    ]
    data = list()
    for r in results:
        data.append([
            r['reference'],
            colorize(r['score'], color=color_cvss(r['score']), attrs='bold') if r['score'] else '',
            textwrap.fill(remove_non_printable_chars(r['title']), 30),
            textwrap.fill(remove_non_printable_chars(r['description']), 50),
            textwrap.fill(r['url'],78),
            r['type'],
        ])

    #pprint.pprint(results)

    info('{} results returned:'.format(len(results)))
    table(columns, data, hrules=True)

# Command-line parsing
# -----------------------------------------------------------------------------
# USAGE = """

# Examples:

# * Mode "all" (requires API key):
#     python3 vulners-lookup.py all --apikey <API-key> "Apache Tomcat 8.5.0"
#     python3 vulners-lookup.py --apikey <API-key> 'affectedSoftware.name:"Microsoft IIS" AND affectedSoftware.version:"6.0"'

# * Mode "software":
# """

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='mode')

parser_all = subparsers.add_parser('all')
parser_all.add_argument(
    '--apikey', 
    help     = 'Vulners API key', 
    action   = 'store', 
    dest     = 'apikey', 
    metavar  = '<API-key>', 
    required = True,
    default  = None
)
parser_all.add_argument('query', help='Query', action='store')

parser_software = subparsers.add_parser('software')
parser_software.add_argument(
    '--name',
    help='Product name',
    action='store',
    dest='name',
    metavar='<name>',
    required=True
)
parser_software.add_argument(
    '--version',
    help='Version number',
    action='store',
    dest='version',
    metavar='<version>',
    required=True,
)

args = parser.parse_args()


# Processing
# -----------------------------------------------------------------------------
if args.mode == 'all':
    global_search(args.apikey, args.query)
elif args.mode == 'software':
    software_api(args.name, args.version)