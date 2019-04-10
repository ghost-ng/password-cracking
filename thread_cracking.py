import hashlib
import binascii
import argparse
import sys, os
import queue
import threading
from time import sleep
# python thread_cracking.py -i hashes.txt -d main.txt --threads 2 --debug -v -y
# GLOBAL VARIABLES
result = os.system('color')  ## Allows the script to use colors
args = ''
GREEN = '\033[92m'
RED = '\033[31m'
YELLOW = '\033[93m'
RSTCOLORS = '\033[0m'
WHITE = '\033[37m'
BLINK = '\033[5m'

#Create queue
queue = queue.Queue(30)
threads =[]
dictionary =""
successes = [] ##list of tuples  [(hash,password),(hash,password)]
save_file = ""
lock = threading.Lock()

class ThreadClass(threading.Thread):
    global save_file
    global successes
    def __init__(self, queue):
        threading.Thread.__init__(self)
    #Assign thread working with queue
        self.queue = queue
        self._stopevent = threading.Event()
        self._sleepperiod = 1.0


    def join(self, timeout=None):
        """ Stop the thread. """
        self._stopevent.set()
        threading.Thread.join(self, timeout)

    def run(self):
        found = False
        q_done = False
        while q_done is not True:
            if self.queue.empty():
                if args.debug:
                    print("[Debug] Queue is empty, Quitting...")
                    #self.queue.join()
                    self.thread.join()
                    break
            else:
                if args.debug:
                    print("[Debug] Current Queue Size:",self.queue.qsize())


        #Get from queue job

            #print(type(self.queue.get()))
            #print("[Debug] Current Queue Size:", self.queue.qsize())
            try:
                (hash,username) = self.queue.get()
            except TypeError as e:
                if args.debug:
                    print("[Debug] Unable to retrieve from queue:")
                    print(e)
            try:
                self.queue.task_done()
            except ValueError as e:
                if args.debug:
                    print("[Debug] Unable to end task, may be already done.  Error:")
                    print(e)
            if args.debug:
                print("[Debug] {} Retrieved From Queue: {}".format(self.getName(),(hash,username)))
            if len(successes) > 0:
                if args.verbose:
                    print("[*] {}: Checking known matches first".format(self.getName()))
                for hash_cracked, password_cracked in successes:
                    if args.debug:
                        print("[Debug] Comparing: Prev Found: {} - New Password Hash: {}".format(hash_cracked,hash))
                    if hash.upper() == hash_cracked.upper():
                        #result = "{} {}:{}".format(self.getName(), username, password.rstrip())
                        result = "{}:{}".format(username, password.rstrip())
                        if args.verbose:
                            print("[+] Match Found:", result)
                        if args.stdout:
                            print(result)
                        found = True
                        self.finish_tasks()
                        break
                if found is False and args.debug is True:
                    print("[Debug] Did not find a match in previously cracked hashes")
            if found is False:
                with open(dictionary, "r", encoding="utf-8") as dict_file:
                    for password in dict_file:
                        if args.debug:
                            print("[Debug] Retrieved {} from dictionary".format(password.rstrip()))
                        password_hash = create_hash(password.rstrip())
                        if args.debug:
                            print("[Debug] Returned hash: {}".format(password_hash))
                        if args.verbose:
                            print("[*] Comparing: Loaded Hash - {}; Wordlist Hash - {}".format(hash.upper(), password_hash.upper()))
                        if hash.upper() == password_hash.upper():
                            #result = "{} {}:{}".format(self.getName(), username, password.rstrip())
                            result = "{}:{}".format(username,password.rstrip())
                            if args.verbose:
                                print("[+] Match Found:",result)
                            if args.stdout:
                                print(result)
                            #save_file.write(result + "\n")
                            #lock.acquire()
                            successes.append((hash,password.rstrip()))        #all matches get added to a list
                            #lock.release()

                            dict_file.seek(0)

                            break

                self.finish_tasks()
            #q_done = True

    def finish_tasks(self):
        try:
            self.queue.task_done()
        except:
            if args.debug:
                print("[Debug] Unable to finish task")

def spawn_threads(num_threads):
    if args.verbose:
        print("[+] Spawning {} Threads".format(num_threads))
    # Create number process
    for i in range(num_threads):
        t = ThreadClass(queue)
        t.setDaemon(False)
        if args.verbose:
            print("[+] Spawning", t.getName())
        # Start thread
        t.start()
        threads.append(t)

def kill_threads(num_threads):
    # wait on the queue until everything has been processed
    if args.debug:
        print("[Debug] Killing Threads")
    for i in range(num_threads):
        queue.put(None)
    print("[*] Emptied Queue")
    for i in threads:
        i.self.join()
        if args.debug:
            print("[Debug] Killed",i)
        #i.is_alive()


def create_hash(password):
    if args.debug:
        print("[Debug] Received {} password to hash".format(repr(password)))
    password = password.replace('\ufeff',"")
    bin_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    string_hash = binascii.hexlify(bin_hash).decode()
    string_hash = string_hash.rstrip()
    if args.debug:
        print("[Debug] Returning hash: {}".format(string_hash))
    return string_hash

def extract_hash_from_line(line):
    temp = line.split(":")
    hash = temp[1].rstrip()
    #hash = hash.rstrip()
    username = temp[0].rstrip()
    #username = username.rstrip()
    return hash,username

def load_hashes(hash_file):
    with open(hash_file, "r", encoding="utf-8") as hash_file:
        count = 0
        for line in hash_file:
            hash,username = extract_hash_from_line(line)
            # Put line to queue
            queue.put((hash,username))
            count += 1
    if args.verbose:
        print("[+] Loaded {} hashes for cracking".format(count))
    if args.debug:
        print("[Debug] Queue Size:",queue.qsize())

#####BEGIN FILE FUNCTIONS#####
##############################
##############################

def file_checks(file, type):
    exists = os.path.isfile(file)  # initial check
    msg = (RED + "[!] Unable to find {} file, try again: " + RSTCOLORS).format(type)
    while exists is False:
        file = input(msg)
        exists = os.path.isfile(file)
    filename, file_extension = os.path.splitext(file)
    return file, filename, file_extension

def check_format(file):
    with open(file, 'r', encoding='utf-8') as f:
        line = f.readline().strip()
        line = line.rstrip(":")
        temp = line.split(":")
        if len(temp) > 2:
            if args.verbose:
                print("[*] Format:", "pwdump")
            # input()
            return 'pwdump'
        else:
            if args.verbose:
                print("[*] Format:", "Pre-Formatted")
            # input()
            return 'pre-formatted'

def clean_up(input_file, input_filename, input_file_extension):
    clean_filename = input_filename + "_clean.txt"

    with open(input_file, 'r', encoding='utf-8') as hash_file:
        with open(clean_filename, 'w+', encoding='utf-8') as new_file:
            for line in hash_file:
                temp = line.strip()
                temp = temp.rstrip(":")
                temp = temp.replace('"', "")
                temp = temp.rstrip()
                temp_list = temp.split(":")
                username = temp_list[0]
                #lm_hash = temp_list[len(temp_list) - 2]
                nt_hash = temp_list[len(temp_list) - 1]
                #new_file.write(username + ":" + lm_hash + "\n")
                new_file.write(username + ":" + nt_hash + "\n")

    return clean_filename

######END FILE FUNCTIONS######
##############################
##############################
def main():
    global args
    global dictionary
    global save_file

    banner_art = """

                     |\                         __3__          |         
____|\_______________|\\_______________|_______'__|__`___|_____|___|__________
____|/___3_|________@'_\|__|_____|_____|___|___|__|__|___|_|__@'___|___|___|__
___/|____-_|____________|__|_____|____@'___|__@'_@'_@'___|_|______@'___|___|__
__|_/_\__4_|___|_______@'__|____O'_________|____________O'_|__________@'___|__
___\|/_____|___|___________|_______________|_______________|_______________|__
    /         O'                                                  

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
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=help_banner)
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-i', dest='inputfile', action='store', default=False, help='Input File')
    parser.add_argument('-d', dest='dictfile', action='store', default=False, help='Dictionary File')
    parser.add_argument('-v', dest='verbose', action='store_true', default=False, help='Be verbose')
    parser.add_argument('-y', dest='force_yes', action='store_true', default=False, help='Force yes on prompts')
    group.add_argument('--hash', dest='single_hash', action='store', default=False,
                       help='Try to crack a single nt hash')
    parser.add_argument('--threads', dest='num_threads', action='store', default=1,type=int,
                        help='spawn multiple threads to crack faster with more processing power consumption')
    parser.add_argument('--quiet', dest='stdout', action='store_true', default=True,
                        help='supress output to the terminal')
    parser.add_argument('--debug', dest='debug', action='store_true', default=False,
                        help='print debug text')

    # TODO add support to change the cracked save file name

    args = parser.parse_args()
    if args.debug:
        print(args)
    if args.single_hash is not False:
        input_file = args.single_hash.rstrip()
    elif args.inputfile is False:
        input_file = input(WHITE + "[?] Input File: " + RSTCOLORS)
        input_file, input_filename, input_file_extension = file_checks(input_file, 'input')
    else:
        input_file = args.inputfile
        input_file, input_filename, input_file_extension = file_checks(input_file, 'input')

    if args.dictfile is False:
        dict_file = input(WHITE + "[?] Dictionary File: " + RSTCOLORS)
    else:
        dict_file = args.dictfile
    dict_file, dict_filename, dict_file_extension = file_checks(dict_file, 'dictionary')
    dictionary = dict_file

    # new_cracked_file = input_filename + "_cracked.txt"
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
            print(RSTCOLORS)
            if args.force_yes is False:
                ans = input("[?] Continue to overwrite? [Y/N] ")
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

    if args.single_hash is False:
        load_hashes(input_file)             #load hashes into the worker queue
        with open(new_cracked_file,'w',encoding='utf-8') as save_file:
            spawn_threads(args.num_threads)     #spawn worker threads
        print("[*] Joining Queues...")
        queue.join()
        print("[*] Killing Threads...")
        kill_threads(len(threads))
    #start_cracking(input_file, dict_file)


try:
    main()
    #print("Done!")
    sys.exit(0)
except KeyboardInterrupt:
    print("\n[!] Quitting...")
    sys.exit(0)

