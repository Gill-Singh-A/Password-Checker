import hashlib
import requests
import sys
from colorama import Fore, Back, Style

def request_password_data(query):
    url = "https://api.pwnedpasswords.com/range/" + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error! Response Code {res.status_code}")
    return res

def get_password_leaks_count(response, hashed_password):
    passwords = [password.split(':') for password in response.text.split('\n')]
    for password in passwords:
        if hashed_password == password[0]:
            return int(password[1])
    return 0

def check_password(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    response = request_password_data(hashed_password[:5])
    return get_password_leaks_count(response, hashed_password[5:].upper())

def main(args):
    for argument in args:
        with open(argument, 'r', encoding='ansi') as file:
            passwords = file.readlines()
            passwords = [password[:len(password)-(password[-1]=='\n')] for password in passwords]
            with open("Checked "+argument, 'w') as output:
                for password in passwords:
                    password = str(password)
                    leaks = str(check_password(password))
                    output.write(f"{password} : {leaks}\n")
                    print(f"{Fore.BLUE}[+]{Fore.GREEN}{Style.BRIGHT} {password} {Fore.RESET}: {Fore.RED}{Back.MAGENTA}{leaks}{Fore.RESET}{Style.RESET_ALL}{Back.RESET}")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))