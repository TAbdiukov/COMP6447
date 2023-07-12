import sys 
from subprocess import check_output, PIPE
from pwn import *
import re, json

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
        
context.log_level = "error"

def pwrn(text):
    print bcolors.WARNING + str(text) + bcolors.ENDC
def pgrn(text):
    print bcolors.OKGREEN + str(text) + bcolors.ENDC
def pbrk():
    print("\n")
    print bcolors.OKBLUE + "*"*80 + bcolors.ENDC
    print bcolors.OKBLUE + "*"*80 + bcolors.ENDC
    print("\n")
    

def start_up():
    try:
        full_path = sys.argv[1]
    except IndexError as e:
        print "Usage: python scanner.py FULL_PATH_TO_BINARY"
        exit()
    return full_path

def check_security(b):
    pgrn("SECURITY CONTROLS\n")
    print(b.checksec())
    pgrn("\nEASY SEC CONTROLS\n")
    print("Stack Executable: ".ljust(len("PIE - do base adress change: ")-3) + str(not b.nx))
    print("Canary Enabled: ".ljust(len("PIE - do base adress change: ")-3) + str(b.canary))
    print("GOT RELRO: ".ljust(len("PIE - do base adress change: ")-3) + str(b.relro))
    print("PIE - do base change: ".ljust(len("PIE - do base adress change: ")-3) + str(b.pie))

def get_binary(path_to_binary):
    binary = ELF(path_to_binary)
    return binary

def contains_win(b):
    for f in b.functions:
        if f == "win":
            pgrn("BINARY CONTAINS WIN FUNCTION")
            return True
    
    pgrn("BINARY DOESNT CONTAIN WIN")

def loop_over_labels(b):
    pwrn("Methods in the binary are: \n")
    for f in b.functions:
        if "." in f or "__" in f: 
            continue

        func = b.functions[f]
        pgrn(f)
        pwrn("Address: " + hex(func.address))
        pwrn("Size: " + hex(func.size))

def search_for_overflow_functions(b, func_hash, got_hash):
    print(got_hash)
    for f in b.functions:
        if "." in f or "__" in f: 
            continue

        func = b.functions[f]
        for line in b.disasm(func.address, func.size).split("\n"):
            if re.search("call", line):
                split_call = line.split(" ")
                length = len(split_call)
                try:
                    try:
                        name = func_hash[int(split_call[length-1],16)]
                        print(name)
                    except:
                        name = got_hash[int(split_call[length-1],16)]
                        print(name)
                except:
                    pass

def get_call_hash(b):
    ret_hash = {}
    for f in b.functions:
        ret_hash[b.functions[f].address] = b.functions[f].name
    return ret_hash

def get_call_stack(b):
    func_hash = get_call_hash(b)
    inv_plt = {v: k for k, v in b.plt.iteritems()}
    call_hash = {}
    for f in b.functions:
        if "." in f or "__" in f: 
            continue

        func = b.functions[f]
        call_hash[f] = { "lib_calls": [], "user_calls": [] }
        for line in b.disasm(func.address, func.size).split("\n"):
            if re.search("call", line):
                split_call = line.split(" ")
                length = len(split_call)
                try:
                    try:
                        lib_call = str(inv_plt[int(split_call[length-1],16)])
                    except KeyError as e:
                        user_call = func_hash[int(split_call[length-1],16)]

                    if "." not in lib_call or "__" not in lib_call: 
                        call_hash[f]["lib_calls"].append(lib_call)

                    if "." not in user_call or "__" not in user_call: 
                        call_hash[f]["user_calls"].append(user_call)
                except:
                    pass
                        
    pwrn("Calls Stacks. A calls [] functions ( not ordered ) \n")
    for k in call_hash.keys():
        print("{}{}{}{}{}:{} {}{}{}".format(bcolors.OKBLUE, "[USER]: ".ljust(10), bcolors.ENDC, bcolors.WARNING, k.ljust(12), bcolors.ENDC, bcolors.OKGREEN, call_hash[k]["user_calls"], bcolors.ENDC))
        print("{}{}{}{}{}:{} {}{}{}\n".format(bcolors.OKBLUE, "[LIB]: ".ljust(10), bcolors.ENDC, bcolors.WARNING, k.ljust(12), bcolors.ENDC, bcolors.OKGREEN, call_hash[k]["lib_calls"], bcolors.ENDC))
    return True



def indicate_injection(b):
    func_hash = get_call_hash(b)
    inv_map = {v: k for k, v in b.plt.iteritems()}
    if b.nx and not b.canary: 
        print("You shoud look for buffer overflow into shellcode")
    if b.nx and b.canary: 
        print("You shoud look for buffer overflow. There is a canary though. Try find memory leak then shellcode")
    
    if b.nx:
        pwrn("Looking for buffer overflow injections... \n")
        search_for_overflow_functions(b, func_hash, inv_map)
    if b.relro in ["None", None, "Partial"]:
        pwrn("Relocation ... \n")

        

fp = start_up()
b = get_binary(fp)
pbrk()
check_security(b)
pbrk()
contains_win(b)
pbrk()
get_call_stack(b)
