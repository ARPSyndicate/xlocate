#!/usr/bin/python3

import requests
import sys
import optparse
import concurrent.futures
import json
import csv
import io
import re

BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

print(BLUE + "Xlocate[1.2] by ARPSyndicate" + CLEAR)
print(YELLOW + "the ultimate exploit finder" + CLEAR)

if len(sys.argv) < 2:
    print(RED + "[!] ./xlocate --help" + CLEAR)
    sys.exit()

else:
    parser = optparse.OptionParser()
    parser.add_option('-k', '--keyword', action="store", dest="keys",
                      help="list of keyword to search [jira,wordpress]", default=False)
    parser.add_option('-c', '--cveid', action="store", dest="cves",
                      help="list of cveid to search [cve-2020-1937,cve-2020-1938]", default=False)
    parser.add_option('-v', '--verbose', action="store_true",
                      dest="verbose", help="enable logging", default=False)
    parser.add_option('-t', '--threads', action="store",
                      dest="threads", help="threads [50]", default=50)
    parser.add_option('-o', '--output', action="store", dest="output",
                      help="file for storing the json output", default=False)
    parser.add_option('-s', '--sources', action="store", dest="sources",
                      help="sources to use [cvemon,exploitdb]", default="cvemon,exploitdb")

inputs, args = parser.parse_args()
if not inputs.keys and not inputs.cves:
    parser.error(RED + "[!] input not given" + CLEAR)
keywords = str(inputs.keys).split(",")
cveids = str(inputs.cves).split(",")
sources = str(inputs.sources).split(",")
verbose = inputs.verbose
output = str(inputs.output)
threads = int(inputs.threads)
result = {}


def get_pocs_cvem():
    response = requests.get(
        "https://raw.githubusercontent.com/ARPSyndicate/cvemon/master/data.json")
    return response.json()


def get_pocs_exdb():
    response = requests.get(
        "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv")
    data = []
    csvio = io.StringIO(response.text, newline="")
    for row in csv.DictReader(csvio):
        data.append(row)
    return data


def query_cveb(cve):
    global cveb
    response = requests.get(
        "https://raw.githubusercontent.com/olbat/nvdcve/master/nvdcve/"+cve+".json")
    summary = response.json(
    )['cve']['description']['description_data'][0]['value']
    if verbose:
        print(GREEN+"[CVEMON] "+cve+CLEAR)
    for keyword in keywords:
        if re.search(keyword, summary, re.IGNORECASE):
            for poc in cveb[cve]:
                print(BLUE + "["+keyword+"] " + poc + CLEAR)
            if keyword in result.keys():
                result[keyword].extend(cveb[cve])
            else:
                result[keyword] = cveb[cve]


def query_exdb(keyword):
    global exdb
    for exp in exdb:
        if verbose:
            print(GREEN+"[EXPLOITDB] "+exp['id']+CLEAR)
        if re.search(keyword, exp['description'], re.IGNORECASE):
            poc = "https://www.exploit-db.com/raw/"+exp['id']
            if keyword in result.keys():
                if poc not in result[keyword]:
                    print(BLUE + "["+keyword+"] " + poc + CLEAR)
                    result[keyword].append(poc)
            else:
                print(BLUE + "["+keyword+"] " + poc + CLEAR)
                result[keyword] = [poc]


if inputs.keys:
    if "cvemon" in sources:
        print(GREEN + "[*] gathering exploits from cvemon" + CLEAR)
        cveb = get_pocs_cvem()
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            try:
                executor.map(query_cveb, cveb.keys())
            except(KeyboardInterrupt, SystemExit):
                executor.shutdown(wait=False)
                sys.exit()

    if "exploitdb" in sources:
        print(GREEN + "[*] gathering exploits from exploitdb" + CLEAR)
        exdb = get_pocs_exdb()
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            try:
                executor.map(query_exdb, keywords)
            except(KeyboardInterrupt, SystemExit):
                executor.shutdown(wait=False)
                sys.exit()

if inputs.cves:
    print(GREEN + "[*] gathering exploits from cvemon" + CLEAR)
    cveb = get_pocs_cvem()
    for cve in cveids:
        if cve.upper() in cveb.keys():
            for poc in cveb[cve.upper()]:
                print(BLUE + "["+cve+"] " + poc + CLEAR)
            if cve in result.keys():
                result[cve].extend(cveb[cve.upper()])
            else:
                result[cve] = cveb[cve.upper()]


if inputs.output and len(result) > 0:
    for key in result.keys():
        result[key] = list(set(result[key]))
        result[key].sort()
    with open(output, "w") as f:
        f.write(json.dumps(result, indent=4, sort_keys=True))

print(GREEN + "[*] done" + CLEAR)
