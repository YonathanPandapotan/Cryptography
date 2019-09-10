class VigenereCipher:
    alphabets = "abcdefghijklmnopqrstuvwxyz"
    text = None
    keyInput = None
    mode = None
    result = None

    def __init__(self, text, keyInput):
        # masukkan nilai pesan yang ingin di ubah dan nilai key-nya
        self.text = text
        self.keyInput = keyInput

    def encrypt(self):
        self.result = ""
        kpos = []

        # Mendapatkan nilai angka pada key
        for x in self.keyInput:
            kpos.append(self.alphabets.find(x))

        # Variable i disini akan menjadi patokan key mana yang akan digunakan per karakter
        i = 0

        for x in str(self.text):
            # Jika karakter bukan merupakan huruf maka langsung tambahkan ke hasil
            if x.isalpha():

                # Jika value i sama dengan panjang key, maka kembalikan nilai i jadi 0
                if i == len(kpos):
                    i = 0

                pos = self.alphabets.find(x) + kpos[i]
                if pos > 25:
                    pos = pos - 26
                self.result += self.alphabets[pos].capitalize()
                i += 1
            else:
                self.result += x
        print(self.result)

    def decrypt(self):
        self.result = ""
        kpos = []
        for x in self.keyInput:
            kpos.append(self.alphabets.find(x))
        i = 0
        for x in str(self.text):
            if x.isalpha():
                if i == len(kpos):
                    i = 0
                pos = self.alphabets.find(x.lower()) - kpos[i]
                if pos < 0:
                    pos = pos + 26
                self.result += self.alphabets[pos].lower()
                i += 1
            else:
                self.result += x

        print(self.result)


if __name__ == "__main__":
    text = VigenereCipher("yonathan" , "asd")
    text.encrypt()
