
class CaesarCipher:
    L2I = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", range(26)))
    I2L = dict(zip(range(26), "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    plaintext = None
    key = None

    def __init__(self, plaintext, key):
        self.plaintext = plaintext
        self.key = key

    def encrypt(self):
        ciphertext = ""
        for c in self.plaintext.upper():
            if c.isalpha():
                ciphertext += self.I2L[(self.L2I[c] + self.key) % 26]
            else:
                ciphertext += c
        print(ciphertext)

    def decrypt(self):
        plaintext2 = ""
        for c in self.plaintext.upper():
            if c.isalpha():
                plaintext2 += self.I2L[(self.L2I[c] - self.key) % 26]
            else:
                plaintext2 += c
        print(plaintext2)


if __name__ == "__main__":
    test = CaesarCipher("KAZMFTMZ", 12)
    test.decrypt()
