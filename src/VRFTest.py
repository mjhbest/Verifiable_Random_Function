from VRF_Sortition import Sortition


def read_participants(fd):
    lst = []
    while True:
        line = fd.readline()
        if not line: break
        lst.append(line[:-1])
    return lst


class Test:
    def __init__(self,fd):
        self.samplelst = read_participants(fd)
        print("Sample List : {}".format(self.samplelst))

    def test(self,id):
        sortition = Sortition(id)
        pick = sortition.pick_winner(self.samplelst,1)
        print("Picked Members : {} , PrivateKey : {} , Proof : {} ".format(pick,sortition.Key.PublicKey,sortition.Proof))
        print("Verify?? : {}".format(sortition.verify_sortition(pick,pick[2])))


ID = 0xa12ab265
if __name__ == '__main__':
    fd = open("test.txt",'r')
    vrfTest = Test(fd)
    vrfTest.test(ID)
    fd.close()





