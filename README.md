# Password Checker
Checks the number of time a given password has been breached through API of pwnedpasswords

## Requirements
Languange Used = Python3
Modules/Packages used:
* hashlib
* requests
* sys
* colorama

## Input
The program takes file names as input (text files containing list of passwords). Due to security reasons, specifying passwords through Command Line Interface is not implemented (passwords can be seen using command history).<br />
For example:
```bash
python password_checker.py file_1 file_2 ...
```
<!-- -->
Install the dependencies:
```bash
pip install -r requirements.txt
```

## Output
The program outputs the checked passwords on the command line interface in the format
```bash
[+] password : number_of_breaches
```
The program also creates file/files with name = "Checked {file_name}" in which the format is same as that of the output in Command Line Interface