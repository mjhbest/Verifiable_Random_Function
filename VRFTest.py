from VRF import  *
from random  import randint


class Test:
    def __init__(self):
        self.samplelst = []
        for i in range(randint(1, 100)):
            self.samplelst.append(randint(1, 1000))
        print("Sample List : {}".format(self.samplelst))

    def test(self):
        vrf = VRF()
        pick = vrf.sampling(self.samplelst)
        print(pick)

if __name__ == '__main__':
    vrfTest = Test()
    vrfTest.test()



