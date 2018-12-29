from binascii import hexlify
from random import SystemRandom
from .math import numberFrom, multiply
from .curve import curvesByOid, supportedCurves
from .der import fromPem, removeSequence, removeInteger, removeObject, removeOctetString, removeConstructed
from .publicKey import PublicKey
from .curve import sm2p256v1


class PrivateKey:

	def __init__(self, curve=sm2p256v1, secret=None):
		self.curve = curve
		self.secret = secret or SystemRandom().randrange(1, curve.N)

	def publicKey(self):
		curve = self.curve
		xPublicKey, yPublicKey = multiply((curve.Gx, curve.Gy), self.secret, A=curve.A, P=curve.P, N=curve.N)
		return PublicKey(xPublicKey, yPublicKey, curve)

	def toString(self):
		return "020{}".format(str(hex(self.secret))[2:-1])

	@classmethod
	def fromPem(cls, string):
		privkeyPem = string[string.index("-----BEGIN EC PRIVATE KEY-----"):]
		return cls.fromDer(fromPem(privkeyPem))

	@classmethod
	def fromDer(cls, string):
		s, empty = removeSequence(string)
		if empty != "":
			raise Exception("trailing junk after DER privkey: %s" % hexlify(empty))

		one, s = removeInteger(s)
		if one != 1:
			raise Exception("expected '1' at start of DER privkey, got %d" % one)

		privkeyStr, s = removeOctetString(s)
		tag, curveOidStr, s = removeConstructed(s)
		if tag != 0:
			raise Exception("expected tag 0 in DER privkey, got %d" % tag)

		oidCurve, empty = removeObject(curveOidStr)
		if empty != "":
			raise Exception("trailing junk after DER privkey curve_oid: %s" % hexlify(empty))

		curve = curvesByOid.get(oidCurve)
		if not curve:
			raise Exception("Unknown curve with oid %s. I only know about these: %s" % (
				oidCurve, ", ".join([curve.name for curve in supportedCurves]))
			)

		if len(privkeyStr) < curve.length():
			privkeyStr = "\x00" * (curve.lenght() - len(privkeyStr)) + privkeyStr

		return cls.fromString(privkeyStr, curve)

	@classmethod
	def fromString(cls, string, curve=sm2p256v1):
		return PrivateKey(secret=numberFrom(string), curve=curve)