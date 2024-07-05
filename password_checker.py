#! /usr/bin/env python3

import hashlib
import requests
import sys
from datetime import date
from optparse import OptionParser
from time import strftime, localtime, time
from colorama import Fore, Back, Style


status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

api = "https://api.pwnedpasswords.com/range/"
api_request_hash_length = 5

def check_passwords(hash_passwords):
    display(':', f"Pre-processing Data for Requests")
    password_leaks = {}
    api_request_hashes = {}
    for hash in hash_passwords.keys():
        if hash[:api_request_hash_length] not in api_request_hashes.keys():
            api_request_hashes[hash[:api_request_hash_length]] = []
        api_request_hashes[hash[:api_request_hash_length]].append(hash)
    display('+', f"Done Pre-processing Data for Requests")
    for api_request_hash, hashes in api_request_hashes.items():
        response = requests.get(f"{api}{api_request_hash}")
        if response.status_code != 200:
            display('-', f"Returned Status Code = {Back.YELLOW}{response.status_code}{Back.RESET} for Hash Request : {Back.MAGENTA}{api_request_hash}{Back.RESET}")
            continue
        hash_leaks = {line.split(':')[0]: int(line.split(':')[1].strip()) for line in response.text.split('\n')}
        print('\n'.join(f"{Fore.GREEN}{hash}{Fore.WHITE}:{Fore.BLUE}{hash_passwords[hash]}{Fore.WHITE} => {Fore.RED}{hash_leaks[hash[api_request_hash_length:]]}{Fore.RESET}" for hash in hashes if hash[api_request_hash_length:] in hash_leaks.keys()))
        password_leaks.update({hash_passwords[hash]: int(hash_leaks[hash[api_request_hash_length:]]) for hash in hashes if hash[api_request_hash_length:] in hash_leaks.keys()})
    return password_leaks

def main(arguments):
    for argument in arguments:
        with open(argument, 'rb') as file:
            display(':', f"Loading Passwords from  File {Back.MAGENTA}{argument}{Back.RESET}")
            passwords = file.read().decode(errors="ignore").split('\n')
            display('+', f"Loaded {Back.MAGENTA}{len(passwords)}{Back.RESET} Passwords from  File {Back.MAGENTA}{argument}{Back.RESET}")
            display(':', f"Making SHA Hashes of Passwords")
            t1 = time()
            hashed_passwords = {hashlib.sha1(password.encode()).hexdigest().upper(): password for password in passwords}
            hashes = list(hashed_passwords.keys())
            hashes.sort()
            hashed_passwords = {hash: hashed_passwords[hash] for hash in hashes}
            t2 = time()
            display('+', f"Done Making SHA Hashes of Passwords")
            display(':', f"Time Taken = {Back.MAGENTA}{t2-t1:.2f} seconds{Back.RESET} {Back.MAGENTA}{len(hashes)/(t2-t1):.2f} hashes/seconds{Back.RESET}")
            password_leaks = check_passwords(hashed_passwords)
            with open(f"Checked {argument}", 'w') as output_file:
                output_file.write('\n'.join([f"{password}:{leaks}" for password, leaks in password_leaks.items()]))

if __name__ == "__main__":
    main(sys.argv[1:])