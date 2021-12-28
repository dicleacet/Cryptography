import hashlib,hmac #Hash fonksiyonları içerir
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


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
        return sha3_512.finalize()

    def sifreSha2_512(self,word):
        sha2_512 = hashes.Hash(hashes.SHA256())
        sha2_512.update(self.Sifre)
        return sha2_512.finalize()

    def sifreBlake2b(self,word):
        blake2 = hashes.Hash(hashes.BLAKE2b(64))
        blake2.update(self.Sifre)
        return blake2.finalize()

    def sifreMD5(self,word):
        md5 = hashes.Hash(hashes.MD5())
        md5.update(self.Sifre)
        return md5.finalize()
    
    def sifreSHA1(self,word):
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(self.Sifre)
        return sha1.finalize()

    def sifreSymmetric(self,word):#Cipher Algorithm
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(word.encode('utf-8')) + encryptor.finalize()
        return ct

    def sifreasymmetric(self,word):#Ed25519 signing Algorithm
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        encrypted = public_key.encrypt(
            word.encode('utf-8'),
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
                )
            )
        print(encrypted)
    
    def __help__(self):
        return "selam kızlar"

class helper:
    def __init__(self):
        pass
    
    def dilKontrol(self):
        print("dil kontrol yapmaktadır")



try:
    dosya = open("şifrelenmemişVeri.txt", "r")
    word = dosya.read()
except IOError:
    print("bir hata oluştu!")
finally:
    dosya.close()



sifreleme = sifrelemeYontemleri(word)
sifreleme.help()
# sifreleme.sifreSha3_512(word)
# sifreleme.sifreSha2_512(word)
# sifreleme.sifreSHA1(word)
# sifreleme.sifreBlake2b(word)
# sifreleme.sifreSymmetric(word)
# sifreleme.sifreMD5(word)
# sifreleme.sifreasymmetric(word)

help(helper)
help(helper.dilKontrol())