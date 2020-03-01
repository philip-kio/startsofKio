import requests
import hashlib
import sys


def request_apidata(querry_char):
    url = 'https://api.pwnedpasswords.com/range/' + querry_char
    res = requests.get(url)
    if res.status_code != 200:
        return RuntimeError(f'error fetching {res.status_code}, check the api')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        print(h, count)
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sh1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sh1[:5], sh1[5:]
    response = request_apidata(first5_char)
    print(response)
    return get_password_leaks_count(response, tail)


# sha1= hashlib.sha1(password.encode('utf-8'))
#  #check if password exist in api respose

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count}, you should probably change it')
        else:
            print(f'{password} was not found')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
