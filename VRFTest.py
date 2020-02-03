import VRF_Sortition


class Test:
    def __init__(self,fd):
        self.samplelst = str(fd.read)
        print("Sample List : {}".format(self.samplelst))

    def test(self):
        sortition = Sortition(self.samplelst,1)
        pick = sortition.pick_winner()
        print("Picked Members : {} , PrivateKey : {} , Proof : {} ".format(pick,sortition.Key.PublicKey,sortition.Proof))
        print("Verify?? : {}".format(sortition.verify_sortition(pick,pick[2])))

if __name__ == '__main__':
    fd = open("test.txt",'r')
    vrfTest = Test(fd)
    vrfTest.test()
    fd.close()



