#! /usr/bin/env python3

import hashlib
import requests
import sys
from datetime import date
from optparse import OptionParser
from multiprocessing import Pool, cpu_count, Lock
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

thread_count = cpu_count()
lock = Lock()
api = "https://api.pwnedpasswords.com/range/"
api_request_hash_length = 5

def handleRequests(thread_index, hashes):
    responses = {}
    for index, hash in enumerate(hashes):
        t1 = time()
        response = requests.get(f"{api}{hash}")
        t2 = time()
        time_taken = t2-t1
        if response.status_code != 200:
            with lock:
                display('-', f"Returned Status Code = {Back.YELLOW}{response.status_code}{Back.RESET} for Hash Request : {Back.MAGENTA}{hash}{Back.RESET}")
            continue
        responses[hash] = response
        with lock:
            display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{hash}{Fore.RESET} ({Fore.GREEN}{(index+1)}/{len(hashes)} ({(index+1)*100/len(hashes):.2f}%){Fore.RESET})")
    return responses
def check_passwords(hash_passwords):
    display(':', f"Pre-processing Data for Requests")
    password_leaks = {}
    api_request_hashes = {}
    for hash in hash_passwords.keys():
        if hash[:api_request_hash_length] not in api_request_hashes.keys():
            api_request_hashes[hash[:api_request_hash_length]] = []
        api_request_hashes[hash[:api_request_hash_length]].append(hash)
    display('+', f"Done Pre-processing Data for Requests")
    display(':', f"Starting {Back.MAGENTA}{thread_count}{Back.RESET} Request Threads")
    request_hashes = list(api_request_hashes.keys())
    total_request_hashes = len(request_hashes)
    request_hashes_divisions = [request_hashes[group*total_request_hashes//thread_count: (group+1)*total_request_hashes//thread_count] for group in range(thread_count)]
    threads = []
    responses = {}
    pool = Pool(thread_count)
    for index, request_hashes_division in enumerate(request_hashes_divisions):
        threads.append(pool.apply_async(handleRequests, (index, request_hashes_division, )))
    for thread in threads:
        responses.update(thread.get())
    pool.close()
    pool.join()
    for api_request_hash, response in responses.items():
        hashes = api_request_hashes[api_request_hash]
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