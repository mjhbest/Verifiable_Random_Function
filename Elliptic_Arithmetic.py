class Point:
    b = 7
    def __init__(self, y = BASEy, x):
        self.y = BASEy
        if y == BASEy:
            self.x = from_y(BASEy).x

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
            if i&n:
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
    x = n**(1./3) if n>=0 else -((-n)**(1./3))
    return Point(x, y)

BASEy = 1