#!/usr/bin/env python

"""
TODO:
* QR Code receipts (Line 188)
* mySQL instead of using a csv for tickets?
* Implement blockchain
"""
#Imports
import argparse, base64, hashlib, csv, fileinput, os, random, sys, django.utils.crypto, time, qrcode
from bcrypt import gensalt
from collections import Counter
from Crypto.Cipher import AES
from Crypto import Random
from string import ascii_uppercase
from secretsharing import PlaintextToHexSecretSharer
from fpdf import FPDF

__author__ = "S. Bean, Peter Aaby, Charley Celice, Sean McKeown"
__version__ = "0.5"


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
        #Have to encode in b64 as the has includes '$' and bash treats them as vars
        new_ticket = hashlib.sha256(voter_rnd + gensalt()).hexdigest()
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
            hashlib.sha256(("%s%s%s" % (random.getstate(), time.time(), more_random)).encode('utf-8')).digest()
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
        rows = csv.reader(database, delimiter=',')
        arows = [row for row in rows if voter_ticket in row]
        database.close()
    if len(arows) <= 0:
        print("!== Ticket does not exits ==!")
        exit(0)

    #Check the blockchain to make sure the ticket hasnt been used
    with open('BLOCKCHAIN1.CSV', 'rb') as bc:
        reader = csv.reader(bc, delimiter='\n')
        for row in reader:
            for data in row:
                if data.split(',')[0] == voter_ticket:
                    print("!== Ticket has been used ==!")
                    exit(0)

    #Dispkay polling options
    print("Select your option")
    choice = raw_input("A. ABC\nB. DEF\nC. GHI\n")

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
    print("\n[*] Your Ticket:%s\n[*] Your vote:\t%s\n" % (voter_ticket, voter_choice))
    confirm = raw_input("Confirm? y/n\n")
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
        f.write(base64.b64encode(random_key))
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

        receipt_gen(secretshares[2], base64.b64encode(random_key), voter_ticket)
        #Print receipt
        print("\n\n==========POLL RECEIPT==========\n")
        print("[*] Your share: %s" % secretshares[2])
        print("[*] Your key: %s" % base64.b64encode(random_key))
        print("[*] Your ticket: %s" % voter_ticket)
        print("\n================================")
    else:
        print("!== No confomation ==!")
        exit(0)

"""Check all votes"""
def check_votes(myshare_file, blockchainshare_file, voter_ticket, keyfile):

    os.system("clear")
    print("----Vote count & check----")
    #Check ticket exits and has been used
    with open('tickets.csv','rb') as f:
        rows = csv.reader(f, delimiter=',')
        arows = []
        for x in rows:
            if voter_ticket in x:
                arows.append(x)
        #arows = [row for row in rows if voter_ticket in row]
        f.close()
    if len(arows) <= 0:
        print("Ticket does not exist")
        exit(0)
    for data in arows:
        if data[1] == '0':
            print("Ticket valid BUT not used")
            exit(0)

    #Count total votes in blockchain
    with open(blockchainshare_file, 'r') as f:
        reader = csv.reader(f,delimiter=',')
        data = list(reader)
        row_count = len(data)

    print("-> %s total vote(s) in blockchain" % row_count)

    #read local share
    print("-> Local share")
    with open(myshare_file,'r') as f:
        myshare = f.read()
    print("[*] %s" % myshare)

    #Grab the share corresponding to voters ticket from within blockchain
    print("-> Getting share from blockchain")
    with open(blockchainshare_file,'rb') as f:
        reader = csv.reader(f, delimiter='\n')
        for row in reader:
            for data in row:
                if data.split(',')[0] == voter_ticket:
                    blockchain_share = data.split(',')[1]
                    print("\t-> %s" % blockchain_share)

    #connect shares
    print("-> Reassembling shares")
    tmp = [myshare, blockchain_share]
    recovered_vote = PlaintextToHexSecretSharer.recover_secret(tmp)

    #decrypt shares
    print("-> Decrypting shares")
    with open(keyfile, 'r') as f:
        key = f.read()
    f.close()
    cipher = AESCipher(base64.b64decode(key))
    decrypted_vote = cipher.decrypt(recovered_vote)
    print("[*] Your vote was: %s" % decrypted_vote)

"""Upload keys to blockchain"""
def upload_key(privKey, ticket):

    os.system('clear')

    print("----Uploding key to blockchain----")

    #Check they key exits and has been used
    with open('tickets.csv', 'rb') as f:
        rows = csv.reader(f, delimiter=',')
        arows = [row for row in rows if ticket in row]
        f.close()
    if len(arows) <= 0:
        print("!== Ticket does not exits ==!")
        exit(0)
    for data in arows:
        if data[1] == '0':
            print("!== Ticket exists but has not been used ==!")
            exit(0)

    #read key from file
    print("-> Extracting key")
    with open(privKey, 'r') as f:
        key = f.read()


    #Find ticket and share in blockchain and add the privKey next to it
    print("-> Adding key to blockchain")
    with open('BLOCKCHAIN1.csv', 'rb') as f:
        reader = csv.reader(f, delimiter='\n')
        for row in reader:
            for data in row:
                if data.split(',')[0] == ticket:
                    #add key next to share
                    voter_share = data.split(',')[1]
                    f = fileinput.input(files=('BLOCKCHAIN1.csv'))
                    for line in f:
                        with open('BLOCKCHAIN1_tmp.csv', 'a') as f:
                            f.write(line.replace(ticket+","+voter_share, ticket+","+voter_share+","+key))

    os.remove('BLOCKCHAIN1.csv')
    os.rename('BLOCKCHAIN1_tmp.csv', 'BLOCKCHAIN1.csv')


"""Test case"""
def dry_run():
    final_votes = []
    os.system("clear")
    print("----Counting Votes (gov)----")

    with open("BLOCKCHAIN1.csv", 'rb') as f:
        reader = csv.reader(f, delimiter='\n')
        for row in reader:
            for data in row:
                current_ticket = data.split(',')[0]
                with open('gov.csv') as g:
                    readerg = csv.reader(g, delimiter='\n')
                    for rowg in readerg:
                        for datag in rowg:
                            gov_ticket = data.split(',')[0]
                            if current_ticket == gov_ticket:
                                bs_share = data.split(',')[1]
                                gov_share = datag.split(',')[1]
                                voter_key = data.split(',')[2]
                                print("-> Ticket: %s" % current_ticket)
                                print("\tKey: %s" % voter_key)
                                print("\n\tShares:\n\t\tBlockchain: %s\n\t\tGov: %s" % (bs_share, gov_share))

                                tmp = [bs_share, gov_share]
                                recovered_vote = PlaintextToHexSecretSharer.recover_secret(tmp)
                                cipher = AESCipher(base64.b64decode(voter_key))
                                decrypted_vote = cipher.decrypt(recovered_vote)
                                print("\tDecrypted Vote: %s" % decrypted_vote)
                                final_votes.append(decrypted_vote)

    print("\n-> Final vote counting")
    counts = Counter(final_votes)
    for key, value in counts.iteritems():
        print("%s votes for |%s|" % (value, key))


#Pad AES encyption
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

"""AES256 Encryption class"""
class AESCipher:

    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, encoded):
        enc = base64.b64decode(encoded)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

"""QR Code gen"""
def qr_gen(share, key, ticket):

    #Generate qr codes for the receipt
    qr_share = qrcode.make(share)
    qr_key = qrcode.make(key)
    qr_ticket = qrcode.make(ticket)

    qr_share.save('share.png')
    qr_key.save('key.png')
    qr_ticket.save('ticket.png')

"""PDF Receipt gen"""
def receipt_gen(share, key, ticket):

    ipsum = """ Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. """


    qr_gen(share, key, ticket)
    #Setup page
    receipt = FPDF('P', 'mm', (100,350))
    receipt.add_page()
    dynamic_widith = receipt.w - 2*receipt.l_margin


    #Header
    receipt.set_font('Arial', '', 26)
    receipt.cell(0,11, 'Poll Receipt', ln=2, align='C')

    #Print date time
    receipt.set_font('Arial', '', 10)
    receipt.cell(0,5, time.strftime("%d/%m/%Y"), align='C', ln=2)
    receipt.cell(0,10, time.strftime("%H:%M:%S"), align='C', ln=2, border='B')
    #spacer
    receipt.cell(0,5,ln=2)

    #Body
    receipt.set_font('Arial', '', 22 )

    #Personal Share
    receipt.cell(0,10, 'Your Share', align='C', ln=1)
    receipt.image('share.png',w=50,x=25)
    #Private key
    receipt.cell(0,10, 'Your Private Key', align='C', ln=1)
    receipt.image('key.png',w=50,x=25)
    #Personal Share
    receipt.cell(0,10, 'Your ticket', align='C', ln=1)
    receipt.image('ticket.png',w=50,x=25)

    #Spacer
    receipt.cell(0,5,ln=1,border='B')
    receipt.cell(0,10, ln=1)

    #Instructions
    receipt.set_font('Arial', '', 12)
    receipt.multi_cell(dynamic_widith, 4, ipsum, align='L')
    #Save pdf
    receipt.output('Poll Receipt.pdf')

"""Main to deal with args"""
def main(arguments):

    #Deal wth args passed to the script
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-g', '--roll', help="Generate tickets from electoral roll file")
    parser.add_argument('-ps', '--pshare', help="Personal share file(Vote checking)")
    parser.add_argument('-bs', '--bshare', help="BLOCKCHAIN1 share file(vote checking)")
    parser.add_argument('-t', '--ticket', help="Ticket(vote checking)")
    parser.add_argument('-k', '--key', help="Encryption key file(vote checking)")
    parser.add_argument('-u', '--upload', help="Upload key to BLOCKCHAIN1")
    parser.add_argument('-c', '--count',action='store_true' ,help="Count votes from Govs point of view")

    args = parser.parse_args(arguments)

    """Initialise files needed"""
    #gen a fake electoral roll list
    if not os.path.exists('electoral_roll.csv'):
        f = open('electoral_roll.csv', 'w')
        f.write('peter,aaby,AA011520B,01/01/2000,"1 street street Edinburgh, UK"\n')
        f.write('scott,bean,BB568394C,02/02/2001,"2 street street Edinburgh, UK"\n')
        f.write('john,smith,CC739546D,03/03/2003,"3 street street Edinburgh, UK"\n')
        f.write('michal,nash,DD899023E,04/04/2004,"4 street street Edinburgh, UK"\n')
        f.write('bill,buchanan,EE018120F,05/05/2005,"5 street street Edinburgh, UK"\n')
        f.close()

    if not os.path.exists('BLOCKCHAIN1.csv'):
        open('BLOCKCHAIN1.csv','w').close()

    if not os.path.exists('gov.csv'):
        open('gov.csv','w').close()

    #Arg handling
    if args.roll:
        print("Running ticket create")
        create_tickets(args.roll)
    elif args.pshare:
        if args.bshare:
            check_votes(args.pshare, args.bshare, args.ticket, args.key)
    elif args.upload:
        upload_key(args.upload, args.ticket)
    elif args.count:
        dry_run()
    else:
        vote()

if __name__ == '__main__':
    main(sys.argv[1:])
    #receipt_gen('123', '456', 'xyz')
