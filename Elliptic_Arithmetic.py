class Point():
    b = 7

    def __init__(self, x=None, y=None):
        self.x = x
        self.y = y
        if x is None:
            self.x = BASEx
            self.y = BASEy

    def copy(self):
        return Point(self.x, self.y)

    def is_zero(self):
        return self.x > 1e20 or self.x < -1e20

    def neg(self):
        return Point(self.x, -self.y)

    def dbl(self):
        if self.is_zero():
            return self.copy()
        try:
            L = (3 * self.x * self.x) / (2 * self.y)
        except ZeroDivisionError:
            return Point()
        x = L * L - 2 * self.x
        return Point(x, L * (self.x - x) - self.y)

    def add(self, q):
        if self.x == q.x and self.y == q.y:
            return self.dbl()
        if self.is_zero():
            return q.copy()
        if q.is_zero():
            return self.copy()
        try:
            L = (q.y - self.y) / (q.x - self.x)
        except ZeroDivisionError:
            return Point()
        x = L * L - self.x - q.x
        return Point(x, L * (self.x - x) - self.y)

    def mul(self, n):
        p = self.copy()
        r = Point()
        i = 1
        while i <= n:
            if i & n:
                r = r.add(p)
            p = p.dbl()
            i <<= 1
        return r

    def __str__(self):
        return "({:.3f}, {:.3f})".format(self.x, self.y)


def show(s, p):
    print(s, "Zero" if p.is_zero() else p)


def from_y(y):
    n = y * y - Point.b
    x = n ** (1. / 3) if n >= 0 else -((-n) ** (1. / 3))
    return Point(x, y)


BASEx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
BASEy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
a = 0x00
b = 0x07
