
class TransposeCipher:
    space = None
    text = None
    key = None
    col = None
    row = None
    rowFinal = None
    Matrix = None
    num = 0
    result = ""

    def __init__(self, text, key):
        # insert text dan key terlebih dahulu
        self.text = text
        self.key = key

        # tentukan kolom dan rownya
        self.col = key
        self.row = len(text) / key
        # check apakah row kurang untuk menampung jumlah text
        if len(self.text) % self.key != 0:
            self.row += 1

        self.rowFinal = int(self.row)

        # dibuat matrixnya
        self.Matrix = [[' ' for x in range(self.col)] for y in range(self.rowFinal)]

        # membuat dan menambahkan spasi
        self.space = " " * key
        self.text += self.space

    def encrypt(self):
        for i in range(self.rowFinal):
            for j in range(self.col):
                self.Matrix[i][j] = self.text[self.num]
                self.num +=1

        print (self.Matrix)

        for i in range(self.col):
            for j in range(self.rowFinal):
                self.result += self.Matrix[j][i]

        return self.result

    def decrypt(self):
        for i in range(self.col):
            for j in range(self.rowFinal):
                self.Matrix[j][i] = self.text[self.num]
                self.num +=1

        print (self.Matrix)

        for i in range(self.rowFinal):
            for j in range(self.col):
                self.result += self.Matrix[i][j]

        return self.result


if __name__ == "__main__":
    a = TransposeCipher("yonathana", 4)
    print(a.encrypt())