import hashlib,hmac #Hash fonksiyonları içerir
from cryptography.hazmat.primitives import hashes

import secrets
import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import Poly_1305


word = b'selam kizlar. Yani selamin aleykum'

class dilKontrol:
    def __init__(self,word):
        self.word = word

    def kelimeAyir(self):
        Kelimeler = self.word.split(" ")
        return len(Kelimeler)

    def CumleAyir(self):
        Cumleler = self.word.split(".")
        return len(Cumleler)
        
    def sesliHarf(self):
        sesli = ["a", "e", "ı", "i", "o", "ö", "u", "ü"]
        sayac = 0
        for i in self.word.lower():
            for j in sesli:
                if(i == j):
                    sayac += 1
        return print(sayac)
    
    def BuyukUnluUyumu(self):
        kalin_unluler = ['a', 'ı', 'o', 'u']
        ince_unluler =  ['e', 'i', 'ö', 'ü']
        uyanlar = 0
        uymayanlar = 0
        Kelimeler = self.word.split(" ")
        for x in Kelimeler:
            if (sum(x.count(kalin) for kalin in kalin_unluler)) != 0 and (sum(x.count(ince) for ince in ince_unluler)) != 0: 
                uymayanlar +=1 
            else:
                uyanlar += 1
        return uyanlar, uymayanlar

class sifrelemeYontemleri:
    def __init__(self,word): 
        self.Sifre = word        
    
    def sifreSha3_512(self):
        sha3_512 = hashes.Hash(hashes.SHA3_512())
        sha3_512.update(self.Sifre)
        print('Printing output')
        print(sha3_512.finalize())

    def sifreSha2_512(self):
        sha2_512 = hashes.Hash(hashes.SHA256())
        sha2_512.update(self.Sifre)
        print('Printing output')
        print(sha2_512.finalize())

    def sifreBlake2b(self):
        blake2 = hashes.Hash(hashes.BLAKE2b(64))
        blake2.update(self.Sifre)
        print('Printing output')
        print(blake2.finalize())

    def sifreMD5(self):
        md5 = hashes.Hash(hashes.MD5())
        md5.update(self.Sifre)
        print('printing output')
        print(md5.finalize())
    
    def sifreSHA1(self):
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(self.Sifre)
        print('printing output')
        print(sha1.finalize())

    def sifreSymmetric(self):
        salt = secrets.token_bytes(32)
        key = scrypt.hash(self.Sifre, salt, N=2048, r=8, p=1, buflen=32)
        mac = Poly1305.new(key=key, cipher=AES, data=self.Sifre)
        mac_verify = Poly1305.new(data=data, key=key, nonce=nonce,                         
                         cipher=AES)
        try:
            mac_verify.hexverify(mac_digest)
            print('Message Authentication Success')
        except:
            print('Message Authentication Failed')


    
class help:
    def __init__(self):
        pass



c = sifrelemeYontemleri(word)
c.sifreSymmetric()