# credstuffer
Tool for performing automated credential stuffing

```
jmpalk@kali-e:~/credstuffer$ ./credstuffer.py --help
usage: credstuffer.py [-h] [-i INFILE] [-o OUTFILE] [-d DELIMITER] [-t] [-p PASSWORD_PARAM] [-n USERNAME_PARAM]
                      [-x XSRF_PARAM] [-c SUCCESS_CODE] [-k SUCCESS_KEYWORD] [-w WAIT] [-u URL] [-s SPRAY] [-v]
                      [-vv] [-D]

Perform a credential stuffing attack against Azure/M365 or a custom endpoint. Supports testing the same user
repeatedly with different passwords and delays between rounds of testing.

optional arguments:
  -h, --help            show this help message and exit
  -w WAIT, --wait WAIT  Number of minutes to wait in between rounds of testing. Default is 15 minutes
  -u URL, --url URL     Target URL if using something like fireprox; otherwise will directly call the O365 login
                        endpoint
  -s SPRAY, --spray SPRAY
                        Single password to spray with
  -v, --verbose
  -vv, --more-verbose
  -D, --debug

Input/Output:
  -i INFILE, --infile INFILE
                        File with credentials (username, password) one pair per line
  -o OUTFILE, --outfile OUTFILE
                        Output file for results. Default is stuff_results.txt
  -d DELIMITER, --delim DELIMITER
                        Delimiter separating username from password in the credentials file. Default is ','

Custom Target:
  -t, --custom-target   Target custom login endpoint
  -p PASSWORD_PARAM, --password-param PASSWORD_PARAM
                        Password parameter for login form submission
  -n USERNAME_PARAM, --username-param USERNAME_PARAM
                        Username parameter for login form submission
  -x XSRF_PARAM, --xsrf-param XSRF_PARAM
                        Anti-XSRF parameter for form submission
  -c SUCCESS_CODE, --success-code SUCCESS_CODE
                        HTTP response code indicating a successful login
  -k SUCCESS_KEYWORD, --success-keyword SUCCESS_KEYWORD
                        Keyword in response indicating a successful login
```

## Installation
```
$ git clone https://github.com/jmpalk/credstuffer
$ cd credstuffer
$ pip install -r requirements.txt
```
## Description
Credstuffer is a script specifically designed for performing [credential-stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
attacks where you may have more than one possible password for a given
user. By default, credstuffer will stuff credentials into 
`https://login.microsoft.com`, but it can also take a custom url and custom
username and password parameters to use in targeting other services such as
web-based VPN portals. If you identify an anti-csrf token in the login page,
you can also pass that parameter to credstuffer and it will attempt to extract
the token to make well-formed login submissions.

Given a comma-separated list of username/password pairs, credstuffer will
iterate through the list, trying each user once in a given cycle, then 
wait a user-specified number of minutes (default 15) before launching the next
round of authentication attempts. Credstuffer implements this delay in order to
attempt to avoid accounts being locked out during testing. 

When testing against `https://login.microsoft.com`, credstuffer will identify
successful logins, as well as logins where the user is disabled, has some forms
of MFA enabled, or the password is expired (error code identification cribbed 
from dafthack's [MSOLSpray](https://github.com/dafthack/MSOLSpray). Credstuffer
will also detect the occurence of lockouts and prompt the user to see whether 
they want to continue if more than 10 lockouts are detected. Credstuffer will
also track whether accounts have been locked out, do not exist, or have had
their password identified and remove that account from further testing cycles
to save time and further reduce the risk of lockouts.

When testing against a non-standard endpoint, a user may choose to supply either a 
HTTP status code (`-c`) or a keyword (`-k`) in the response indicating a
successful login attempt. If the user supplies one of these, credspray will log
successful attempts in the output file. If the user does not supply a success
condition, credspray will log all authentication attemps with a selection of
metadata, including HTTP status code, redirect URL (if present), response
length, and whether certain words indicating a failed login were detected, so
the user can analyze the results to identify successful login attempts.

## Spray Mode
Credstuffer can also be run as a standard password spraying tool, by supplying
a password on the commandline with the `-s` flag.

## Custom URLs and Fireprox

A user can target a custom URL using the `-u` flag. By itself, this can be used
to route credstuffer requests through a [fireprox](https://github.com/ustayready/fireprox) proxy, in order to avoid 
throttling by Microsoft or another service provider. When using credstuffer 
with fireprox to target the default MS endpoint, the url should contain only
the URL of the fireprox proxy; credstuffer will automatically append 
`common/oauth2/token`. 
e.g:
```
$ ./credstuffer.py -i credentials.txt -u https://<fireprox-api-id>.execute-api.us-east-1.amazonaws.com/fireprox/
```
If using credstuffer with the `-t` flag to target a custom service, the 
provided URL should include the specific endpoint being targeted. e.g.:
```
$ ./credstuffer.py -i credentials.txt -t -u https://some-vpn.fakedomain.com/vpn/login -u user -p password -c 200
```
or
```
$ ./credstuffer.py -i credentials.txt -t -u https://<fireprox-api-id>.execute-api.us-east-1.amazonaws.com/vpn/login -u user -p password -c 200
```


