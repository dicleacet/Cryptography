import hashlib,hmac #Hash fonksiyonları içerir
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
        pass
    
    def sifreSha3_512(self,word):
        sha3_512 = hashes.Hash(hashes.SHA3_512())
        sha3_512.update(self.Sifre)
        print('Printing output')
        print(sha3_512.finalize())

    def sifreSha2_512(self,word):
        sha2_512 = hashes.Hash(hashes.SHA256())
        sha2_512.update(self.Sifre)
        print('Printing output')
        print(sha2_512.finalize())

    def sifreBlake2b(self,word):
        blake2 = hashes.Hash(hashes.BLAKE2b(64))
        blake2.update(self.Sifre)
        print('Printing output')
        print(blake2.finalize())

    def sifreMD5(self,word):
        md5 = hashes.Hash(hashes.MD5())
        md5.update(self.Sifre)
        print('printing output')
        print(md5.finalize())
    
    def sifreSHA1(self,word):
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(self.Sifre)
        print('printing output')
        print(sha1.finalize())

    def sifreSymmetric(self,word):#Cipher Algorithm
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(b"a secret message") + encryptor.finalize()
        return ct

    
class help:
    def __init__(self):
        pass


try:
    dosya = open("şifrelenmemişVeri.txt", "r")
    word = dosya.read()
except IOError:
    print("bir hata oluştu!")
finally:
    dosya.close()

sifreleme = sifrelemeYontemleri(word)
# sifreleme.sifreSha3_512(word)
# sifreleme.sifreSha2_512(word)
# sifreleme.sifreSHA1(word)
# sifreleme.sifreBlake2b(word)
sifreleme.sifreSymmetric(word)
# sifreleme.sifreMD5(word)
