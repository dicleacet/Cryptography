from cryptography.hazmat.primitives import hashes
import os
import pyodbc 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

class dilKontrol:
    def __init__(self):
        self.kalinunluler = ['a', 'ı', 'o', 'u']
        self.unluler = ["a", "e", "ı", "i", "o", "ö", "u", "ü"]
        self.inceunluler = ['e', 'i', 'ö', 'ü']

    def kelimeAyir(self,word):
        Kelimeler = word.split(" ")
        return len(Kelimeler)

    def CumleAyir(self,word):
        Cumleler = word.split(".")
        return len(Cumleler)
        
    def sesliHarf(self,word):
        sayac = 0
        for i in word.lower():
            for j in self.unluler:
                if(i == j):
                    sayac += 1
        return sayac
    
    def BuyukUnluUyumu(self,word):
        uyanlar = 0
        uymayanlar = 0
        Kelimeler = word.split(" ")
        for x in Kelimeler:
            if (sum(x.count(kalin) for kalin in self.kalinunluler)) != 0 and (sum(x.count(ince) for ince in self.inceunluler)) != 0: 
                uymayanlar +=1 
            else:
                uyanlar += 1
        return uyanlar, uymayanlar

class sifrelemeYontemleri:
    def __init__(self): 
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
    
    def sifreSha3_512(self,word):
        sha3_512 = hashes.Hash(hashes.SHA3_512())
        sha3_512.update(word.encode('utf-8'))
        return sha3_512.finalize()

    def sifreSha2_512(self,word):
        sha2_512 = hashes.Hash(hashes.SHA256())
        sha2_512.update(word.encode('utf-8'))
        return sha2_512.finalize()

    def sifreBlake2b(self,word):
        blake2 = hashes.Hash(hashes.BLAKE2b(64))
        blake2.update(word.encode('utf-8'))
        return blake2.finalize()

    def sifreMD5(self,word):
        md5 = hashes.Hash(hashes.MD5())
        md5.update(word.encode('utf-8'))
        return md5.finalize()
    
    def sifreSHA1(self,word):
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(word.encode('utf-8'))
        return sha1.finalize()

    def sifreSymmetric(self,word):#Cipher 
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        encryptor = cipher.encryptor()
        try :
            ct = encryptor.update(word.encode('utf-8')) + encryptor.finalize()
        except ValueError:
            ct = "Şifrelenecek Veri 16 harf olmalıdır."
        return ct

    def sifreasymmetric(self,word):#rsa 
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
        return encrypted

class helper:
    def __init__(self):
        pass
    
    def dilKontrol(self):
        print("\t\t Dil Kontrol Classı")
        print("kelimeAyir => Gönderilen Str'yi kelimelerine ayırmaktadır.")
        print("CumleAyir => Gönderilen Str'yi cümlelerine ayırmaktadır. ")
        print("sesliHarf => Gönderilen Str'nin içerisindeki sesli harflerin sayısını göstermektedir.")
        print("BuyukUnluUyumu => Gönderilen Str'nin içerisindeki kelimelerin arasından büyük ünlü uyumuna uyanların ve uymayanların sayısını vermektedir.")
        
    def sifreleme(self):
        print("\t\t Şifreleme Classı")
        print("sifreSha3_512 => 512 bitlik Sha-3 algoritmasıyla şifrelemeyi sağlayan bir fonksiyondur.")
        print("sifreSha2_512 => 512 bitlik Sha-2 algoritmasıyla şifrelemeyi sağlayan bir fonksiyondur.")
        print("sifreBlake2b => 64 bitlik şifrelemeyi sağlayan fonksiyondur.")
        print("sifreMD5 => 128 bitlik şifrelemeyi sağlayan fonksiyondur.")
        print("sifreSHA1 => 160 bitlik Sha-1 algoritmasıyla şifrelemeyi sağlayan bir fonksiyondur.")
        print("sifreSymmetric => Cipher Algoritmasıyla simetrik şifrelemeyi sağlayan bir fonksiyondur")
        print("sifreasymmetric => RSA Algoritmasıyla asimetrik sifrelemeyi sağlayan bir fonksiyondur.")


try:
    dosya = open("şifrelenmemişVeri.txt", "r",encoding="utf-8")
    word = dosya.read()
except IOError:
    print("Bir hata oluştu!")
finally:
    dosya.close()

#Fonksiyonların Çağırılması
helper().dilKontrol()
dil = dilKontrol()
print("\t\tFonksiyonların Kullanılması")
print("Kelime sayisi",dil.kelimeAyir(word))
print("Cümle sayisi",dil.CumleAyir(word))
print("Sesli harf sayisi",dil.sesliHarf(word))
print("Büyük ünlü uyumuna uyan ve uymayan",dil.BuyukUnluUyumu(word))
#sifreleme 
helper().sifreleme()
sfr = sifrelemeYontemleri()
print("\t\tSifrelemelerin Kullanılması")
print("Sha3 = ",sfr.sifreSha3_512(word))
print("Sha2 = ",sfr.sifreSha2_512(word))
print("blake = ",sfr.sifreBlake2b(word))
print("md5 = ",sfr.sifreMD5(word))
print("sha1 = ",sfr.sifreSHA1(word))
print("simetrik = ",sfr.sifreSymmetric(word))
print("asimetrik = ",sfr.sifreasymmetric(word))

try:
    conn = pyodbc.connect('Driver={SQL Server};'
                        'Server=FAWMAINPC;'
                        'Database=dbTicarii;'
                        'Trusted_Connection=yes;')

    cursor = conn.cursor()
    com = cursor.execute("INSERT INTO dbo.sifreleme (sha3_512,sha2_512,blake2,md5,sha1,cipher,rsa) VALUES (?,?,?,?,?,?,?)",(sfr.sifreSha3_512(word),sfr.sifreSha2_512(word),sfr.sifreBlake2b(word),sfr.sifreMD5(word),sfr.sifreSHA1(word),sfr.sifreSymmetric(word),sfr.sifreasymmetric(word)))
    com.commit()
except:
    print("Cipher Algoritması Şifrelenemedi")
finally: 
    conn.close()