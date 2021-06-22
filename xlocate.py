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

print(BLUE + "Xlocate[1.3] by ARPSyndicate" + CLEAR)
print(YELLOW + "the ultimate exploits/references finder" + CLEAR)

if len(sys.argv) < 2:
    print(RED + "[!] ./xlocate --help" + CLEAR)
    sys.exit()

else:
    parser = optparse.OptionParser()
    parser.add_option('-k', '--keyword', action="store", dest="keys",
                      help="list of keyword to search [jira,wordpress]", default=False)
    parser.add_option('-c', '--cveid', action="store", dest="cves",
                      help="list of cveid to search [CVE-2020-1937,CVE-2020-1938]", default=False)
    parser.add_option('-t', '--threads', action="store",
                      dest="threads", help="threads [100]", default=100)
    parser.add_option('-o', '--output', action="store", dest="output",
                      help="path for json output", default=False)
    parser.add_option('-u', '--unofficial-only', action="store_true", dest="unofficial",
                      help="locates unofficial exploits/references only", default=False)
    parser.add_option('-d', '--database', action="store", dest="database",
                      help="path for database input", default="data.json")

inputs, args = parser.parse_args()
if not inputs.keys and not inputs.cves:
    parser.error(RED + "[!] input not given" + CLEAR)
keywords = str(inputs.keys).split(",")
cveids = str(inputs.cves).split(",")
database = str(inputs.database)
unofficial = inputs.unofficial
output = str(inputs.output)
threads = int(inputs.threads)
result = {}


def get_pocs_cvem():
    if unofficial:
        response = requests.get(
            "https://raw.githubusercontent.com/ARPSyndicate/cvemon/master/unofficial-data.json")
    else:
        response = requests.get(
            "https://raw.githubusercontent.com/ARPSyndicate/cvemon/master/data.json")
    return response.json()


def query_db(exp):
    global data, result
    for keyword in keywords:
        if re.search(keyword, data[exp], re.IGNORECASE):
            if "CVE-" in exp:
                if keyword in result.keys():
                    result[keyword].extend(cvem[exp.upper()])
                else:
                    result[keyword] = cvem[exp.upper()]
            if "EDB-" in exp:
                if keyword in result.keys():
                    result[keyword].append(
                        "https://www.exploit-db.com/raw/"+exp.split("-")[1])
                else:
                    result[keyword] = cvem["https://www.exploit-db.com/raw/" +
                                           exp.split("-")[1]]


if inputs.keys:
    try:
        with open(database) as db:
            data = json.load(db)
    except:
        print(RED + "[!] invalid database" + CLEAR)
    cvem = get_pocs_cvem()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        try:
            executor.map(query_db, list(data.keys()))
        except(KeyboardInterrupt, SystemExit):
            executor.shutdown(wait=False)
            sys.exit()
    for keyword in keywords:
        result[keyword] = list(set(result[keyword]))
        result[keyword].sort()
        for entry in result[keyword]:
            print("{3}[{2}] {0} {1}".format(
                entry, CLEAR, keyword, BLUE))

if inputs.cves:
    cvem = get_pocs_cvem()
    for cve in cveids:
        if cve.upper() in cvem.keys():
            for poc in cvem[cve.upper()]:
                print(BLUE + "["+cve+"] " + poc + CLEAR)
            if cve in result.keys():
                result[cve].extend(cvem[cve.upper()])
            else:
                result[cve] = cvem[cve.upper()]


if inputs.output and len(result) > 0:
    for key in result.keys():
        result[key] = list(set(result[key]))
        result[key].sort()
    with open(output, "w") as f:
        f.write(json.dumps(result, indent=4, sort_keys=True))

print(GREEN + "[*] done" + CLEAR)
