import argparse
from datetime import datetime
import json
import math
import re
import requests
import shutil
import stat
import sys, os
import tempfile
import urllib
from github import Github


def ascii_art():
    print("\n")
    print(r" _                   _     _            _    ")
    print(r"| |_ _ __ __ ___   _(_)___| | ___  __ _| | __")
    print(r"| __| '__/ _` \ \ / / / __| |/ _ \/ _` | |/ /")
    print(r"| |_| | | (_| |\ V /| \__ \ |  __/ (_| |   < ")
    print(r" \__|_|  \__,_| \_/ |_|___/_|\___|\__,_|_|\_\\")
    print("\n\n\n")



class TravisLeak:
	
	def __init__(self, org, members_scan, output):

		self.org = org
		self.members_scan = members_scan
		self.ACCESS_TOKEN = os.environ.get('GITHUB_API_KEY')
		if self.members_scan == True:
			self.github_login()

		self.BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
		self.HEX_CHARS = "1234567890abcdefABCDEF"
		try:
			self.dir = os.mkdir(output)
		except Exception as E:
			print("[--] There was error creating the directory: " + str(E) +" ... \n")
			sys.exit()

		try:
			basedir = os.path.abspath(os.path.dirname(__file__))
			data_file = os.path.join(basedir, 'wordlist.txt')
			with open(data_file) as w:
				self.regexList = w.read().split('\n')
		except Exception as E:
			print(E)
			raise Exception('Cannot open wordlist.txt')


	def shannon_entropy(self, data, iterator):
	    if not data:
	        return 0
	    entropy = 0
	    for x in (ord(c) for c in iterator):
	        p_x = float(data.count(chr(x)))/len(data)
	        if p_x > 0:
	            entropy += - p_x*math.log(p_x, 2)
	    return entropy


	def get_strings_of_set(self, word, char_set, threshold=20):
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

	def store_result(self, target, alert_log):

		try:

			f = open(str(output)+"/"+str(target), "a")
			for alert in alert_log:
				f.write("\n")

				if isinstance(alert, list): 
					for line in alert:
						f.write("\n")
						f.write(line)
				else:
					f.write(alert)
			f.close()
		except Exception as E:
			print(E)


	def get_logs(self, target):

		try:

			try:
				self.headers = {'Travis-API-Version': '3', 'Accept': 'application/json'}
				self.url1 = ("https://api.travis-ci.org/owner/" + target + "/repos")
				self.r = requests.get(self.url1, headers=self.headers)
				self.json_data = (self.r.text)
				self.json_string = json.loads(self.json_data)
				self.slug = []
				self.job_id = []
				for c in self.json_string['repositories']:
					self.slug.append(c["slug"])


				for i in self.slug:
					url2 = "https://api.travis-ci.org/repo/"+ urllib.parse.quote(i, safe='')  +"?include=repository.current_build"
					r2 = requests.get(url2, headers=self.headers)
					json_data2 = (r2.text)
					json_string2 = json.loads(json_data2)
					try:
						for d in json_string2["current_build"]["jobs"]:
							self.job_id.append(d["@href"])
					except:
						print("[-] Job not found")

				alert_log = []

				for j in self.job_id:


					url3 = ('https://api.travis-ci.org/v3' + j +'/log.txt')

					print('\n\n[-] '+url3)
					print("\n[-] ===========================Generating Report===========================\n\n")
					print("-------------")
					print(url3)
					i_alerts = []
					self.r = requests.get(url3, headers=self.headers)
					final_raw=(self.r.text)
					for regex in self.regexList:
						matches = re.finditer(regex, final_raw, re.MULTILINE | re.IGNORECASE)
						for matchNum, match in enumerate(matches, start=1):
							matched = "Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group())
							print ("[+] Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
							i_alerts.append(matched)
							for groupNum in range(0, len(match.groups())):
								groupNum = (groupNum + 1)
								group_match = "Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum))
								print ("[+] Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum)))
								i_alerts.append(group_match)

					words =[word for word in final_raw.split(' ')]
					print("\n\n")
					for word in words:
						foundSomething = False
						base64_strings = self.get_strings_of_set(word, self.BASE64_CHARS)
						hex_strings = self.get_strings_of_set(word, self.HEX_CHARS)
						for string in base64_strings:
							b64Entropy = self.shannon_entropy(string, self.BASE64_CHARS)
							if b64Entropy > 4.5:
								foundSomething = True
								printableDiff = string
						for string in hex_strings:
							hexEntropy = self.shannon_entropy(string, self.HEX_CHARS)
							if hexEntropy > 3:
								foundSomething = True
								printableDiff = string
						if foundSomething:
							matched_something= 'Suspicious string: '+printableDiff
							print('[!] Suspicious string: ',printableDiff)
							i_alerts.append(matched_something)

					alert_log.append(url3)
					alert_log.append(i_alerts)

				if len(alert_log) > 0:	
					self.store_result(target, alert_log)	
		
			except:
				print("[!] %s: User Not Found!" % (target))
		except:
			##print("[!] %s: User Not Found!")
			pass


	def github_login(self):
		try:
			self.g = Github(self.ACCESS_TOKEN)
			user = self.g.get_user()
			print("\n[++] Logged in successfully as " + str(user.name) + "....\n")

		except:
			print("\n [--] GITHUB_API_KEY is not set or not valid .... \n")
			sys.exit()


	def github_members(self):

		try:
			target=  self.g.get_organization(self.org)
			get_members = target.get_members()
			print('\n[++] Found ' + str(get_members.totalCount) + ' members to scan .....\n')
			members = []
			for member in get_members:
				members.append(member.login)

			return members

		except Exception as E:
			print(E)
			sys.exit()



	def main(self):



		print("\n[++] Started scanning " + self.org + " .... \n")
		self.get_logs(self.org)


		if self.members_scan == True:

			try:

				members = self.github_members()


				if len(members) > 0:
					for member in members:

						print("\n[++] Started scanning " + member + " .... \n")
						self.get_logs(member)
				else:

					print("\n[--] There is no members associated with "+ self.org +" .... \n")


			except Exception as E:

				print(E)


ascii_art()


parser = argparse.ArgumentParser(description='TravisLeak Scanner Tool is written in Python3 that scans Organization/User Travis build logs for leaks such as GitHub Token, AWS Access Keys and more. \n\n')
parser.add_argument('-o', '--org', help='Organization name or user account',required=True)
parser.add_argument("-m", "--include-members", help="scan organization's members", action="store_true")
parser.add_argument('-out', '--output', help='Organization name or user account',required=True)
args = parser.parse_args()
org= args.org
members_scan = args.include_members
output= args.output




tl = TravisLeak(org, members_scan, output)
tl.main()



