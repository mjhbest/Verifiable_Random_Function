from ECVRF import  *
from VRF_Sortition import *
from random  import randint


class Test:
    def __init__(self,fd):
        self.samplelst = str(fd.read).split()
        print("Sample List : {}".format(self.samplelst))

    def test(self):
        sortition = Sortition()
        pick = sortition.pickN(n)
        print("Picked Member : {} , PrivateKey : {} , Proof : {} ".format(pick[0],pick.key,pick[1]))
        print("Verify?? : {}".format(sortition.verify_sortition(pick,pick[2])))

if __name__ == '__main__':
    fd = open("test.txt",'r')
    vrfTest = Test(fd)
    vrfTest.test()
    fd.close()



