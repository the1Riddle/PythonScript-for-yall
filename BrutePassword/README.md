# BrutePassword
A simple Python script to brute force a user's password as stored in `/etc/shadow` in a Linux system. It assumes the password is hashed with MD5 and simply tries to compare existing password hashes to hashes of passwords in the dictionary.

# Requirments
1. Python 3.6+
2. `passlib`

# Usage
```bash
# requirements installations
$ pip3 install -r requirements.txt

# show help
$ python3 brute_password.py -h

# run exhaustive search on all passwords in passwords.txt using
# password_dict.txt as dictionary
$ python3 brute_password.py passwords.txt password_dict.txt
```
