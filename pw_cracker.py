import hashlib
import binascii
import argparse
import sys,os

#GLOBAL VARIABLES
result = os.system('color') ## Allows the script to use colors
args = ''
GREEN = '\033[92m'
RED = '\033[31m'
YELLOW = '\033[93m'
RSTCOLORS = '\033[0m'
WHITE = '\033[37m'
BLINK = '\033[5m'


def clean_up(input_file,input_filename,input_file_extension):
    clean_filename = input_filename + "_clean.txt"

    with open(input_file, 'r',encoding='utf-8') as hash_file:
        with open(clean_filename, 'w+', encoding='utf-8') as new_file:
            for line in hash_file:
                temp = line.strip()
                temp = temp.rstrip(":")
                temp = temp.replace('"', "")
                temp = temp.rstrip()
                temp_list = temp.split(":")
                username = temp_list[0]
                lm_hash = temp_list[len(temp_list) - 2]
                nt_hash = temp_list[len(temp_list) - 1]
                new_file.write(username + ":" + lm_hash + "\n")
                new_file.write(username + ":" + nt_hash + "\n")

    return clean_filename

def check_format(file):
    with open(file,'r',encoding='utf-8') as f:
        line = f.readline().strip()
        line = line.rstrip(":")
        temp = line.split(":")
        if len(temp) > 2:
            if args.verbose:
                print("[*] Format:","pwdump")
            #input()
            return 'pwdump'
        else:
            if args.verbose:
                print("[*] Format:", "Pre-Formatted")
            #input()
            return 'pre-formatted'


def file_checks(file,type):
    exists = os.path.isfile(file)       #initial check
    msg = (RED + "[!] Unable to find {} file, try again: " + RSTCOLORS).format(type)
    while exists is False:
        file = input(msg)
        exists = os.path.isfile(file)
    filename, file_extension = os.path.splitext(file)
    return file, filename, file_extension


def start_cracking(input_file,dict_file):
    filename = ''
    print(BLINK + "[*] Time to get jazzy....please be patient, this may take a while!" + RSTCOLORS)
    count = 0

    if args.single_hash is False:
        filename, file_extension = os.path.splitext(input_file)
        if filename.endswith("_clean.txt"):
            cracked_filename = filename[:-10] + "_cracked.txt"
        else:
            cracked_filename = filename + "_cracked.txt"
        with open(input_file,'r',encoding='utf-8') as hash_file:
            with open(dict_file,'r',encoding='utf-8') as password_file:
                with open(cracked_filename,'w+',encoding="utf-8") as new_file:
                    for hash_line in hash_file:
                        line = hash_line.split(":")
                        hash = line[1]
                        hash = hash.rstrip()
                        for password in password_file:
                            password = password.rstrip()
                            password_hash = create_hash(password)
                            if args.verbose:
                                print(WHITE + "[*] Trying {hash:password_hash} " + hash + ":" + password_hash + RSTCOLORS)
                            if password_hash.rstrip() == hash.rstrip():
                                count += 1
                                cracked = line[0] + ":" + password

                                if args.verbose:
                                    print(GREEN + "[*] Match:", cracked + ":" + password_hash + "\n" + RSTCOLORS)
                                if args.stdout:
                                    print(cracked)
                                #input()
                                new_file.write(cracked + "\n")
                                break
                        password_file.seek(0)
    else:
        hash = input_file
        with open(dict_file, 'r', encoding='utf-8') as password_file:
            for password in password_file:
                password = password.rstrip()
                password_hash = create_hash(password)
                if args.verbose:
                    print(WHITE + "[*] Trying {hash:password_hash} " + hash + ":" + password_hash + RSTCOLORS)
                if password_hash.rstrip() == hash.rstrip():
                    print("[+] Cracked: {}::{}".format(password,hash))
                    break
            sys.exit(0)
        print("[-] No matched found!")


def create_hash(password):
    bin_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    string_hash = binascii.hexlify(bin_hash).decode()

    return string_hash

def main():
    global args
    banner_art ="""
    
                     |\                         __3__          |         
____|\_______________|\\_______________|_______'__|__`___|_____|___|__________
____|/___3_|________@'_\|__|_____|_____|___|___|__|__|___|_|__@'___|___|___|__
___/|____-_|____________|__|_____|____@'___|__@'_@'_@'___|_|______@'___|___|__
__|_/_\__4_|___|_______@'__|____O'_________|____________O'_|__________@'___|__
___\|/_____|___|___________|_______________|_______________|_______________|__
    /         O'                                                  
                              ***************
                              *  get-jazzy  *
                              ***************
"""
    print(banner_art)

    help_banner = """
pwdump:
      [username]:[<extra info>]:[lanman hash]:[nt hash]
      Administrator:500:41aa818b512a8c0e72381e4c174e281b:1896d0a309184775f67c14d14b5c365a:::
pre-formatted:
      [username]:[lanman hash]
      [username]:[nt hash]
    
      Administrator:41aa818b512a8c0e72381e4c174e281b
      Administrator:1896d0a309184775f67c14d14b5c365a 
"""

    parser = argparse.ArgumentParser(description='Get jazzy with NTLM dictionary attacks!',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,epilog=help_banner)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', dest='inputfile', action='store', default=False, help='Input File')
    parser.add_argument('-d', dest='dictfile', action='store', default=False, help='Dictionary File')
    parser.add_argument('-v', dest='verbose', action='store_true', default=False, help='Be verbose')
    group.add_argument('--hash', dest='single_hash', action='store', default=False, help='Try to crack a single nt hash')
    parser.add_argument('--stdout', dest='stdout', action='store_true', default=False,
                        help='output passwords to the screen in addition to a file')

    #TODO add support to change the cracked save file name

    args = parser.parse_args()

    if args.single_hash is not False:
        input_file = args.single_hash.rstrip()
    elif args.inputfile is False:
        input_file = input(WHITE + "[?] Input File: " + RSTCOLORS)
        input_file, input_filename, input_file_extension = file_checks(input_file, 'input')
    else:
        input_file = args.inputfile
        input_file, input_filename, input_file_extension = file_checks(input_file,'input')

    if args.dictfile is False:
        dict_file = input(WHITE + "[?] Dictionary File: " + RSTCOLORS)
    else:
        dict_file = args.dictfile
    dict_file, dict_filename, dict_file_extension = file_checks(dict_file,'dictionary')

    #new_cracked_file = input_filename + "_cracked.txt"
    if args.single_hash is False:
        if input_filename.endswith("_clean.txt"):
            new_cracked_file = input_filename[:-10] + "_cracked.txt"
        else:
            new_cracked_file = input_filename + "_cracked.txt"

        new_clean_file = input_filename + "_clean.txt"

        new_cracked_file_exists = os.path.isfile(new_cracked_file)
        new_clean_file_exists = os.path.isfile(new_clean_file)
        if new_clean_file_exists or new_cracked_file_exists:
            print(YELLOW + "[!] Files exists!")
            print("[*] {} - {}".format(new_cracked_file, "Exists: " + str(new_cracked_file_exists)))
            print("[*] {} - {}".format(new_clean_file, "Exists: " + str(new_clean_file_exists)))
            ans = input("[?] Continue to overwrite? [Y/N] " + RSTCOLORS)
            if ans.upper() == "N":
                sys.exit(0)
            else:
                pass
        else:
            pass
        format = check_format(input_file)

        if format == 'pwdump':
            new_file = clean_up(input_file, input_filename, input_file_extension)
            input_file = new_file
    start_cracking(input_file,dict_file)

try:
    main()
except KeyboardInterrupt:
    print("\n[!] Quitting...")

