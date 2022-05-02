import os
import sys
import time
import asyncio
import keyboard
from datetime import datetime
import aioconsole
import concurrent.futures
from concurrent.futures import ProcessPoolExecutor
from getpass import getpass
from telethon import TelegramClient, events
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

messagewaiting = 0
hasquit = 0

def cls():
    os.system('cls' if os.name=='nt' else 'clear')
cls()

async def refresh_disp():
    global mainmenu
    global messagewaiting
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    cls()
    if mainmenu == 1:
        print(f"""MAIN MENU:
        1.Send a message
        2.See messages
        3.Exit/Quit


        Command:""")
        if messagewaiting == 1:
            sys.stdout.write("\033[F\033[F")
            print(f"***MESSAGE WAITING***")
            sys.stdout.write("\n")

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
            print("CALL FUNC TO SEND MESSAGE") 
            mainmenu=True
            await asyncio.sleep(1)
        elif mainmenu == "2":
            print("Await message")
            mainmenu=True
            await asyncio.sleep(1)
        elif mainmenu == "3" or mainmenu == "q":
            print("Goodbye.")
            mainmenu=True
            hasquit = 1
            await asyncio.sleep(1)
            break
        elif mainmenu != "":
            print("Not Valid Choice Try again")
            await asyncio.sleep(1)
            mainmenu=True


async def endprogram():
    await client.disconnect()     

async def heartbeat():
    global messagewaiting
    global hasquit
    global mainmenu
    while True:
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        if hasquit == 1:
            endprogram()
            break

        await asyncio.sleep(1)

@client.on(events.NewMessage)
async def my_event_handler(event):
    global messagewaiting
    messagewaiting = 1
    await refresh_disp()

async def main():
        await asyncio.gather(mainmenu(), heartbeat())

with client:
    client.loop.run_until_complete(main())

"""loop = asyncio.new_event_loop()
loop.create_task(heartbeat())
loop.create_task(mainmenu())
loop.run_forever()"""

#loop = asyncio.get_event_loop()
#executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
#loop.run_until_complete(main(loop, executor))
