class VigenereCipher:
    alphabets = "abcdefghijklmnopqrstuvwxyz"  # this is the english letters
    text = None
    keyInput = None
    mode = None
    cipher = None

    def __init__(self, text, keyInput, cipher):
        self.text = text
        self.keyInput = keyInput
        self.cipher = cipher

    def encrypt(self):
        self.cipher = ""
        kpos = []  # return the index of characters ex: if k='d' then kpos= 3
        for x in self.keyInput:
            # kpos += alphabets.find(x) #change the int value to string
            kpos.append(self.alphabets.find(x))
        i = 0
        for x in str(self.text):
            if x.isalpha():
                if i == len(kpos):
                    i = 0
                pos = self.alphabets.find(x) + kpos[
                    i]  # find the number or index of the character and perform the shift with the key
                # print(pos) there is no need for this to be shown
                if pos > 25:
                    pos = pos - 26  # check you exceed the limit
                self.cipher += self.alphabets[pos].capitalize()  # because the cipher text always capital letters
                i += 1
            else:
                self.cipher += x
        print(self.cipher)

    def decrypt(self):
        self.text = ""
        kpos = []
        for x in self.keyInput:
            kpos.append(self.alphabets.find(x))
        i = 0
        for x in str(self.cipher):
            if x.isalpha():
                if i == len(kpos):
                    i = 0
                pos = self.alphabets.find(x.lower()) - kpos[i]
                if pos < 0:
                    pos = pos + 26
                self.text += self.alphabets[pos].lower()
                i += 1
            else:
                self.text += x

        print(self.text)


if __name__ == "__main__":
    text = VigenereCipher("" , "asd", "YGQALKAF")
    text.decrypt()
