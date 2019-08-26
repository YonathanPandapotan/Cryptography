from random import choice
from math import gcd

class RSACipher:

    no1 = None
    no2 = None
    text1 = None

    def __init__(self, p, q, text1):
        self.no1 = p
        self.no2 = q
        self.text1 = text1

    def encrypt(self):
        p = int(self.no1)
        q = int(self.no2)

        n = p * q
        r = (p - 1) * (q - 1)
        E = []
        for i in range(1, n):
            if (i < n) and (gcd(i, r) == 1):
                E.append(i)

        e = choice(E)
        d = self.modinv(e, r)

        print('P =', p)
        print('Q =', q)
        print('N =', n)
        print('r =', r)
        print('E (public key) =', e)
        print('D (private key) =', d)

        message = self.text1

        print("Message : " + message)
        plainTextDec = []

        for a in message:
            plainTextDec.append(ord(a))

        # mulai enkripsi

        cipherText = []

        for c in plainTextDec:
            cipherText.append(pow(c, e, n))

        # balik dekripsi

        decryptText = []

        for da in cipherText:
            decryptText.append(pow(da, d, n))

        number = [p, q, n, r, e, d]

        finalText = ""
        for a in decryptText:
            finalText = finalText + chr(a)

        return number, message, plainTextDec, cipherText, decryptText, finalText

    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = self.egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def modinv(self, a, m):
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('No modular inverse')
        return x % m


if __name__ == "__main__":
    a = RSACipher(11, 13, "yonathan")
    b, c, d, e, f, g = a.encrypt()
    print (b)
    print(c)
    print(d)
    print(e)
    print(f)
    print(g)


