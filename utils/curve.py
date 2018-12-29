#
# Elliptic Curve Equation
#
# y^2 = x^3 + a*x + b (mod p)
#


class CurveFp:

	def __init__(self, A, B, P, N, Gx, Gy, name):
		self.A = A
		self.B = B
		self.P = P
		self.N = N
		self.Gx = Gx
		self.Gy = Gy
		self.name = name

	def contains(self, x_y):
	  """Is the point R(x,y) on this curve?"""
	  x, y = x_y
	  return (y**2 - (x**3 + self.A * x + self.B)) % self.P == 0

	def length(self):
		return (1 + len("%x" % self.N)) // 2


sm2p256v1 = CurveFp(
	name="sm2p256v1",
	A=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
	B=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
	P=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
	N=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
	Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
	Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
)

supportedCurves = [
	sm2p256v1
]

curvesByOid = {
    (1, 3, 132, 0, 10): sm2p256v1
}