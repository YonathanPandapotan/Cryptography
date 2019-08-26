
class TransposeCipher:
    space = None
    plaintext = None
    key = None
    col = None
    row = None
    rowFinal = None
    Matrix = None
    num = 0
    result = ""

    def __init__(self, plaintext, key):
        self.space = " " * key
        self.plaintext = plaintext
        self.key = key
        self.col = key
        self.row = len(plaintext) / key
        if len(self.plaintext) % self.key != 0:
            self.row += 1

        self.rowFinal = int(self.row)
        self.Matrix = [[' ' for x in range(self.col)] for y in range(self.rowFinal)]
        self.plaintext += self.space

    def encrypt(self):
        for i in range(self.rowFinal):
            for j in range(self.col):
                self.Matrix[i][j] = self.plaintext[self.num]
                self.num +=1

        print (self.Matrix)

        for i in range(self.col):
            for j in range(self.rowFinal):
                self.result += self.Matrix[j][i]

        return self.result

    def decrypt(self):
        for i in range(self.col):
            for j in range(self.rowFinal):
                self.Matrix[j][i] = self.plaintext[self.num]
                self.num +=1

        print (self.Matrix)

        for i in range(self.rowFinal):
            for j in range(self.col):
                self.result += self.Matrix[i][j]

        return self.result


if __name__ == "__main__":
    a = TransposeCipher("yaaotnnh", 3)
    print(a.decrypt())