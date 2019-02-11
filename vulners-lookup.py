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
import vulners
import pprint
import colored
import prettytable
import textwrap

API_KEY = 'JIVPHXNKN9K8EWMVGQVWKX1PEF1GRVSXLTHFBRD31HH0XNGJILQEGCCDVQXILBCM'

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
    cvss = r['cvss']['score']

    if cvss == 0.0:
        try:
            return vulners_api.aiScore(vuln['description'])[0]
        except:
            return 0.0
    else:
        return cvss

def color_cvss(cvss):
    """Attribute a color to the CVSS score"""
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
    print(colorize('[*] ', color='light_blue', attrs='bold') + string)



# Command-line parsing
# -----------------------------------------------------------------------------
USAGE = """

Examples:

- Simple product search:
python3 vulners-lookup.py "Apache Tomcat"

- Simple product search with version:
python3 vulners-lookup.py "Apache Tomcat 8.5.0"

- Search using "affectedSoftware" keyword (more accurate but not always working):
python3 vulners-lookup.py 'affectedSoftware.name:"Microsoft IIS" AND affectedSoftware.version:"6.0"'

"""

parser = argparse.ArgumentParser(usage=USAGE)

parser.add_argument('product', help='Product to look for', action='store')

args = parser.parse_args()


# Processing
# -----------------------------------------------------------------------------
info('Looking for "{}" in Vulners database...'.format(args.product))

vulners_api = vulners.Vulners(api_key=API_KEY)
results = vulners_api.search('{}  order:published'.format(args.product), limit=200)

nb_results = 0
for r in results:
    if r['bulletinFamily'] not in ('info', 'blog', 'bugbounty', 'tools'):
        nb_results += 1

if nb_results == 0:
    info('No result has been found !')
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
    if r['bulletinFamily'] not in ('info', 'blog', 'bugbounty', 'tools'):
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