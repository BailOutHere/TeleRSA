import os
import sys
import time
import random
import asyncio
from datetime import datetime
from weakref import ref
import aioconsole
import concurrent.futures
from concurrent.futures import ProcessPoolExecutor
from getpass import getpass
from telethon import TelegramClient, events
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

mainrunning = False
messagewaiting = 0
hasquit = 0
runningchats = []
displaymessage = " "

def cls():
    os.system('cls' if os.name=='nt' else 'clear')
    #print("Cls")
cls()

async def refresh_disp():
    now = datetime.now()
    if mainmenu == True:
        cls()
        print(f"""MAIN MENU:
            1.Send a message
            2.See messages
            3.Edit config
            4.Exit/Quit
            {displaymessage}

            Command:""")
    if mainmenu == "waitwindow":
        cls()
        i = 0
        print(f"""WAITING MENU: q to return.
                {displaymessage}""")
        if runningchats:
            for chat in runningchats:
                if not chat:
                    break
                if not chat.members:
                    break
                if chat.rsanick == '':
                    print(str(i), ". User:" + chat.members[0])
                else:
                    print(str(i), ". Group:" + chat.rsanick)
                i += 1
        print("Command:")
    if mainmenu == "chatwindow":
            cls()
            print(f"""Chat menu: q to return.
                    {displaymessage}""")
            for line in runningchats[int(chatnumglob)].plainmessagehistory:
                print(line)
            print("Message:")

def AESdecrypt(key, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()

def AESencrypt(key, plaintext):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

class keybunch:
    def __init__(self, private_key=None, public_key=None, public_key_serial=None):
        self.private_key=private_key
        self.public_key=public_key
        self.public_key_serial=public_key_serial

    def GenerateKeys(self, exponent=65537, size=2048):
        self.private_key = rsa.generate_private_key(
        public_exponent=exponent,
        key_size=size,
        )
        self.public_key = self.private_key.public_key()
        self.public_key_serial = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

def RSAencryptToHex(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()

def RSAdecryptFromHex(ciphertext):
    plaintext = mykeys.private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


def LoadAPI(username):
    apipath = username + "_api.enc"
    if os.path.exists(apipath):
        #Open and read file into variables
        apifile = open(apipath, 'rb')
        unstriplines = apifile.readlines()
        lines = []
        for i in range(len(unstriplines)):
            lines.append(unstriplines[i].strip(b'\n'))
        salt = lines[0]
        iv = lines[1]
        api_enc = lines[2]
        tag = lines[3]
        #Init kdf to convert password into usable SHA256 key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        #Derive key from password
        print(apipath, "found.")
        key = kdf.derive(bytes(getpass("API file Password:"), encoding='utf8'))
        api_plain = AESdecrypt(key, iv, api_enc, tag).decode("utf-8") 
        api_id = api_plain.split(",")[0]
        api_hash = api_plain.split(",")[1]
        print("api.txt read, good schitt.")
        return api_id, api_hash
    else:
        print(apipath, "not found. Please enter your API details and a password to encrypt them.")
        api_id = input("Please enter your api id: ")
        api_hash = input("Please enter your api hash: ")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = kdf.derive(bytes(getpass("API file Password:"), encoding='utf8'))
        api_plain = bytes(str(api_id + "," + api_hash), encoding='utf8')
        iv, api_enc, tag = AESencrypt(key, api_plain)
        lines = []
        lines.append(salt)
        lines.append(iv)
        lines.append(api_enc)
        lines.append(tag)
        with open(apipath, 'wb') as f:
            for item in lines:
                f.write(bytes("%s\n", encoding='utf-8') % item)
        print("These values have be stored in", apipath, "\b, which has been AES-256 encrypted using the password you have given.")
        return api_id, api_hash

username = input("Please enter the username you wish to use: ")
api_id, api_hash = LoadAPI(username)
client = TelegramClient(username, api_id, api_hash)
#client.start()
mykeys = keybunch()
mykeys.GenerateKeys()
##sys.stdout.write("\033[F") # Cursor up one line
# ^^^ THIS WILL BE HANDY FOR HANDLING FUCKY INPUT STUFF.

async def mainmenu():
    global mainmenu
    global messagewaiting
    global hasquit
    mainmenu=True
    
    while mainmenu:
        await refresh_disp()
        mainmenu=await aioconsole.ainput() 
        if mainmenu == "1":
            await sendinitmsg()
            mainmenu = "waitwindow"
            await waitwindow()
            mainmenu=True
        elif mainmenu == "2":
            mainmenu = "waitwindow"
            await waitwindow()
            mainmenu=True
        elif mainmenu == "3":
            print("CONFIG MENU")
        elif mainmenu == "4" or mainmenu == "q":
            print("Goodbye.")
            mainmenu=False
            hasquit = 1
            break
        elif mainmenu != "":
            print("Not Valid Choice (Main Menu) Try again")
            await asyncio.sleep(1)
            mainmenu=True
## CHAT HEADERS
##      TELERSA:(CHATID):(CONTROL MESSAGE):(DATA)
##e.g.  TELERSA:37291:MESSAGE:DA45A6F9E9A0........
class rsa_chat:
    def __init__(self, rsachatid, isrunning, rsanick, members=None, membercerts=None, plainmessagehistory=None):
        self.rsachatid = rsachatid
        self.isrunning = isrunning
        self.rsanick = rsanick
        if members is None:
            members = []
        self.members = members

        if membercerts is None:
            membercerts = []
        self.membercerts = membercerts

        if plainmessagehistory is None:
            plainmessagehistory = []
        self.plainmessagehistory = plainmessagehistory

#Ongoing message stream
#eventmessage.rsachatid
#eventmessage.rsactrlmsg
#eventmessage.rsadata
#eventmessage.sender
"""async def msgHandler(chat, message):
    for member, i in enumerate(chat.members):
        if member == message.sender.username:
            ciphertext = str(message.rsadata)
            plaintext = AES.decrypt(
                bytes.fromhex(ciphertext),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            me = await client.get_me()
            print("\n", peer_username, "\b:", plaintext.decode())            
"""
async def msgHandler(chat, message):
    try:
        chat.plainmessagehistory.append(current_time + " " + message.rsasender.username + ": " + RSAdecryptFromHex(message.rsadata))
        if chat.rsanick == "":
            return f"***Message from {message.rsasender.username}***", chat
        else:
            return f"***Message in {chat.rsanick} chat***", chat
    except:
        if chat.rsanick == "":
            return f"***ERROR in decoding message from {message.rsasender.username}***", chat
        else:
            return f"***ERROR in decoding message in {chat.rsanick} chat***", chat


async def sendinitmsg():
    global runningchats
    peerusername=await aioconsole.ainput("Username (Without @) or Phone number (Starting with +) to establish connection with: ")
    rsachatid=str(random.randint(1,1000000))
    runningchats.append(rsa_chat(rsachatid, True, ''))
    message = "TeleRSA:"+ rsachatid  + ':DM_INIT:' + mykeys.public_key_serial.decode("utf-8")
    await client.send_message(peerusername, message)
    return f"***Init sent to{peerusername}***"

async def dmrxinitmsgHandler(eventmessage):
    global runningchats
    runningchats.append(rsa_chat(eventmessage.rsachatid, True, ''))
    runningchats[-1].members.append(eventmessage.rsasender.username)
    runningchats[-1].membercerts.append(eventmessage.rsadata)
    message = "TeleRSA:"+ eventmessage.rsachatid  + ':DM_INIT_RPL:' + mykeys.public_key_serial.decode("utf-8")
    await client.send_message(eventmessage.rsasender.username, message)
    return f"***Init received from {eventmessage.rsasender.username}***"

async def dminitrplmsgHandler(eventmessage):
    global runningchats
    for chat in runningchats:
        if chat.rsachatid == eventmessage.rsachatid:
            chat.members.append(eventmessage.rsasender.username)
            peer_public_key_serial = str(eventmessage.rsadata)
            chat.membercerts.append(serialization.load_pem_public_key(peer_public_key_serial.encode()))
            return f'***Connection established with{eventmessage.rsasender.username}***'



async def endChat():
    print("Chat ended (This client Leave)")

async def sendErr(message):
    print(f"Would've sent an error here, that cool? Username was: {message.rsasender.username}")
    #await client.send_message(message.sender.user_id, 'TELERSA:ERR:ERR:UNKNOWN ERROR. DELETE CLASS ASSOCIATED WITH THIS CHAT.')

async def errorRx(message):
    print(f'Error Rxd from {message}')

async def endprogram():
    await client.disconnect()     

async def progheartbeat(x):
    global now
    global current_time
    while True:
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        if hasquit == 1:
            await endprogram()
            break

        await asyncio.sleep(x)

async def chatheartbeat(x):
    while True:
        #print("Send heartbeat ctrl message")
        await asyncio.sleep(x)
        if hasquit == 1:
            await endprogram()
            break


@client.on(events.NewMessage(pattern=r'TeleRSA:*'))
async def newmessageevent(eventmessage):
    global runningchats
    global displaymessage
    if mainrunning:
        eventmessage.rsachatid = eventmessage.raw_text.split(':')[1]
        eventmessage.rsactrlmsg = eventmessage.raw_text.split(':')[2]
        eventmessage.rsadata = eventmessage.raw_text.split(':')[3]
        eventmessage.rsasender = await eventmessage.get_sender()
        displaymessage = ''
        if eventmessage.rsactrlmsg == 'MSG':
            for chat in runningchats:
                if chat.rsachatid == eventmessage.rsachatid:
                    displaymessage, chat = await msgHandler(chat, eventmessage)
            #"***MESSAGE FROM" + eventmessage.username + "***"
        if eventmessage.rsactrlmsg == 'DM_INIT':
            displaymessage = await dmrxinitmsgHandler(eventmessage)
        #if eventmessage.rsactrlmsg == 'GC_INIT':
            #displaymessage = await gcinitmsgHandler(eventmessage)
        if eventmessage.rsactrlmsg == 'DM_INIT_RPL':
            displaymessage = await dminitrplmsgHandler(eventmessage)
        #if eventmessage.rsactrlmsg == 'DM_INIT_RPL':
            #displaymessage = await gcrplinitmsgHandler(eventmessage)
            #"***CHAT INITIATED WITH" + eventmessage.username + "***"
        #elif eventmessage.rsachatid == '0' and eventmessage.rsactrlmsg == 'RES':
            #displaymessage = await initmsgHandler(eventmessage)
            # Placeholder for resume, if I want to make sessions persist, one day :)        
        elif eventmessage.rsachatid == 'ERR':
            displaymessage = await errorRx(eventmessage)
            #"***Error recieved from" + eventmessage.sender.username + "***"
        #else:
            #displaymessage = await sendErr(eventmessage)
            #"***Unknown error from" + eventmessage.sender.username + ". Error message sent back to them.***"
            
        await refresh_disp()

async def waitwindow():
    global mainmenu
    global displaymessage
    await refresh_disp()
    userinput=True
    while userinput:
        userinput=await aioconsole.ainput()
        if userinput == "q":
            return
        if not runningchats[int(userinput)]:
            displaymessage = "No running chats. Breaking."
        waitchat = runningchats[int(userinput)]
        if not waitchat.members:
            displaymessage = "Chat has no members. Breaking."
            break
        mainmenu = 'chatwindow'
        await chatwindow(userinput)
        userinput=True
        refresh_disp()


async def chatwindow(chatnum):
    global mainmenu
    global runningchats
    global chatnumglob
    global displaymessage
    chatnumglob = chatnum
    usermessage=True
    while usermessage:
        await refresh_disp()
        usermessage=await aioconsole.ainput()
        if usermessage == "q":
            return
        else:
            runningchats[int(chatnum)].plainmessagehistory.append(current_time + " " + username + ": " + usermessage)
            message = "TeleRSA:"+ runningchats[int(chatnum)].rsachatid  + ':MSG:' + RSAencryptToHex(usermessage, serialization.load_pem_public_key(str(runningchats[int(chatnum)].membercerts[0]).encode()))
            #displaymessage = "Send "+ message + "to " + runningchats[int(chatnum)].members[0]
            await client.send_message(runningchats[int(chatnum)].members[0], message)
            usermessage = True
        

async def main():
    global mainrunning
    mainrunning = True
    await asyncio.gather(mainmenu(), progheartbeat(1), chatheartbeat(10))

with client:
    client.loop.run_until_complete(main())

"""loop = asyncio.new_event_loop()
loop.create_task(heartbeat())
loop.create_task(mainmenu())
loop.run_forever()"""

#loop = asyncio.get_event_loop()
#executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
#loop.run_until_complete(main(loop, executor))
