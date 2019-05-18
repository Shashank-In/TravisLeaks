import argparse
import datetime
import json
import math
import re
import requests
import shutil
import stat
import sys
import tempfile
import urllib


uname = sys.argv[1]
headers = {'Travis-API-Version': '3', 'Accept': 'application/json'}
url1 = ("https://api.travis-ci.org/owner/" + uname + "/repos")
r = requests.get(url1, headers=headers)
json_data = (r.text)
json_string = json.loads(json_data)
slug = []
job_id = []

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

try:
	with open('wordlist.txt') as w:
		regexList = w.read().split('\n')
except:
	raise Exception('Cannot open wordlist.txt')


def shannon_entropy(data, iterator):
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


for c in json_string['repositories']:
	slug.append(c["slug"])

for i in slug:
	url2 = "https://api.travis-ci.org/repo/"+ urllib.parse.quote(i, safe='')  +"?include=repository.current_build"
	r2 = requests.get(url2, headers=headers)
	json_data2 = (r2.text)
	json_string2 = json.loads(json_data2)
	try:
		for d in json_string2["current_build"]["jobs"]:
			job_id.append(d["@href"])
	except:
		print("Job not found")


for j in job_id:
	url3 = ('https://api.travis-ci.org/v3' + j +'/log.txt')
	print("-------------")
	print(url3)
	r = requests.get(url3, headers=headers)
	final_raw=(r.text)
	for regex in regexList:
		matches = re.finditer(regex, final_raw, re.MULTILINE | re.IGNORECASE)
		for matchNum, match in enumerate(matches, start=1):
			print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
			for groupNum in range(0, len(match.groups())):
				groupNum = (groupNum + 1)
				print ("Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum)))


	words =[word for word in final_raw.split(' ')]
	for word in words: 
		foundSomething = False
		base64_strings = get_strings_of_set(word, BASE64_CHARS)
		hex_strings = get_strings_of_set(word, HEX_CHARS)
		for string in base64_strings:
		    b64Entropy = shannon_entropy(string, BASE64_CHARS)
		    if b64Entropy > 4.5:
		        foundSomething = True
		        printableDiff = string
		for string in hex_strings:
		    hexEntropy = shannon_entropy(string, HEX_CHARS)
		    if hexEntropy > 3:
		        foundSomething = True
		        printableDiff = string
		if foundSomething:
		    print('Suspicious string:',printableDiff)


