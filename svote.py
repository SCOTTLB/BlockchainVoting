#!/usr/bin/env python

"""
TODO:
* QR Code receipts (Line 188)
* mySQL instead of using a csv for tickets?
* Implement blockchain
"""
#Imports
import argparse, base64, bcrypt, csv, fileinput, os, random, sys, django.utils.crypto
from collections import Counter
from Crypto.Cipher import AES
from Crypto import Random
from string import ascii_uppercase
from secretsharing import PlaintextToHexSecretSharer

__author__ = "S. Bean, Peter Aaby, Charley Celice, Sean McKeown"
__version__ = "0.5"

#Pad AES encyption
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


""" Gen tickets based on electoral roll """
def create_tickets(roll_data):

    #Get electoral roll data
    print("-> Getting electoral roll data from file...")
    with open(roll_data, 'rb') as file:
        reader = csv.reader(file)
        electoral_list = list(reader)

    #Gen unique tickets
    print("-> Generating tickets and shuffling")
    for voters in electoral_list:
        voter_rnd = ''.join(voters).replace(" ", "") + random_gen()

        #Gen a hash of the above voter_rnd and add a field to check if the tickets been used
        new_ticket = bcrypt.hashpw(voter_rnd, bcrypt.gensalt())
        print("-> %s" % new_ticket)
        tmp = []
        tmp.append(new_ticket)
        tmp.append("0")

        #Append ticket to a database and then shuffled to preserve privacy
        with open("tickets.csv", "a") as ticktsf:
            wr = csv.writer(ticktsf, lineterminator='\n')
            wr.writerow(tmp)

        shuffle()

"""Shuffle lines in a file"""
def shuffle():
    with open("tickets.csv","r") as source:
        data = [ (random.random(), line) for line in source ]
        data.sort()

    with open("tickets_tmp.csv", "w") as target:
        for _, line in data:
            target.write(line)

    os.remove("tickets.csv")
    os.rename("tickets_tmp.csv", "tickets.csv")


"""Generate a randomised string"""
def random_gen(length=20, allowed_chars='abcdefghijklmnopqrstuvwxyz''ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):

    #Try use system random
    try:
        random_test = random.SystemRandom()
        using_sysrandom = True
    except:
        using_sysrandom = False

    more_random = (''.join(random.choice(ascii_uppercase) for i in range(20)))

    #If cannot use system random, create own
    if not using_sysrandom:
        random.seed(
            hashlib.sha256(
                ("%s%s%s" % (random.getstate(), time.time(), more_random)).encode('utf-8')
                ).digest()
            )
        )

    return ''.join(random.choice(allowed_chars) for i in range(length))

"""Test voting method"""
def vote():
    os.system('clear')

    print("---- TEST POLL BOOTH ----")
    #Get voter ticket
    voter_ticket = raw_input("Enter ticket: ")

    #Check ticket is legit
    with open('tickets.csv', 'rb') as database:
        rows = csv.reader(datatbase, delimiter=',')
        arows = [row for row in rows if voter_ticket in row]
        database.close()
    if len(arows) <= 0:
        print("!== Ticket does not exits ==!")
        exit(0)

    #Check the blockchain to make sure the ticket hasnt been used
    with open('BLOCKCHAIN1.CSV', 'rb') as bc:
        reader = csv.reader(bc, dialect='\n')
        for row in reader:
            for data in row:
                if data.split(',')[0] == voter_ticket:
                    print("!== Ticket has been used ==!")
                    exit(0)

    #Dispkay polling options
    print("Select your option")
    choice = raw_input("A. ABC\nB. DEF\nC. GHI")

    if choice == 'A' or choice == 'a':
        voter_choice = 'ABC'
    elif choice == 'B' or choice == 'b':
        voter_choice = 'DEF'
    elif choice == 'C' or choice == 'c':
        voter_choice = 'GHI'
    else:
        print("Unknown choice!")
        exit(0)

    #Display conformation
    print("\n[*] Your Ticket:\t%s\n[*] Your vote:\t%s\n" % voter_ticket, voter_choice)
    confirm = raw_input("Confirm? y/n")
    if confirm == 'y' or confirm == 'Y':
        print ""

        #Vote must be encrypted, split and ticket marked as used
        #Encrypt vote
        print("-> Encrypting vote")
        random_key = os.urandom(32)
        cipher = AESCipher(random_key)
        encrypted_vote = cipher.encrypt(voter_choice)

        #Save encryption key
        f = open("privKey.txt", "w")
        f.write(base64.encode(random_key))
        f.close()
        print("-> Key saved locally as privKey.txt")

        #Create 3 secret shares
        print("-> Creating shares")
        #Split into 3 votes that only require 2 to be used
        secretshares = PlaintextToHexSecretSharer.split_secret(encrypted_vote,2,3)

        #Add used ticket plus share 1 to blockchain
        print("-> Submitting share 1 to BLOCKCHAIN")
        with open("BLOCKCHAIN1.csv", 'a') as fp:
            wr = csv.writer(fp, lineterminator='\n')
            tmp = []
            tmp.append(voter_ticket)
            tmp.append(secretshares[0])
            wr.writerow(tmp)

        #Add share 2 to government
        print("-> Submitting share 2 to Government")
        with open("gov.csv", 'a') as fp:
            wr = csv.writer(fp, lineterminator='\n')
            tmp = []
            tmp.append(voter_ticket)
            tmp.append(secretshares[1])
            wr.writerow(tmp)

        #Save share 3 locally
        f = open("myshare.txt", 'w')
        f.write(secretshares[2])
        f.close()
        print("-> Saved share 3 locally as myshare.txt")

        #Mark ticket as used in ticket database
        f = fileinput.input(files=('tickets.csv'))
        for line in f:
            with open('tickets_tmp.csv', 'a') as f:
                f.write(line.replace(voter_ticket+",0", voter_ticket+",1"))

        os.remove('tickets.csv')
        os.rename("tickets_tmp.csv", "tickets.csv")

        #Print receipt
        print("\n\n==========POLL RECEIPT==========\n")
        print("[*] Your share: %s" % secretshares[2])
        print("[*] Your key: %s" % base64.encode(random_key))
        print("[*] Your ticket: %s" % voter_ticket)
    else:
        print("!== No confomation ==!")
        exit(0)
