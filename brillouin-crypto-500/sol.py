from base64 import b64encode, b64decode
from bls.scheme import setup
from bplib.bp import G1Elem, G2Elem
from petlib.bn import Bn
from pwn import *
import sys
from hashlib import sha256

def hash(elements):
  Cstring = b",".join([str(x) for x in elements])
  return  sha256(Cstring).digest()

params = setup()
(G, o, g1, g2, e) = params

def lagrange_basis(t, o, i, x=0):
	numerator, denominator = 1, 1
	for j in range(1,t+1):
		if j != i:
			numerator = (numerator * (x - j)) % o
			denominator = (denominator * (i - j)) % o 
	return (numerator * denominator.mod_inverse(o)) % o

def sign(params, sk, m):
	assert len(m) > 0
	(G, o, g1, g2, e) = params
	digest = hash(m)
	h = G.hashG1(digest)
	sigma = sk*h
	return sigma

# attack
io = remote("crypto.chal.csaw.io", 1004)
io.recvline()
io.recvline()
io.recvline()
p1 = io.recvline()
io.recvline()
p2 = io.recvline()
io.recvline()
p3 = io.recvline()

io.recv()
io.sendline("3")
io.recv()
io.sendline("this stuff")
io.recvline()
# signature of p3 for message "this stuff"
s3 = io.recvline()

io.recv()
io.sendline("4")
io.recvline()
io.recvline()


# generating a new public key
b = 3
pk = b*g2
m = "this stuff"
# signature of my key for message "this stuff"
sm = sign(params, b, m)

p3_point = G2Elem.from_bytes(b64decode(p3), G)
s3_point = G1Elem.from_bytes(b64decode(s3), G)

io.sendline(b64encode(sm.export()))
io.recv()
io.sendline(b64encode(p3_point.export()))
io.recv()
io.sendline(b64encode(s3_point.export()))
io.recv()
io.sendline(b64encode(p3_point.export()))
io.recv()
io.sendline(b64encode((pk + pk - p3_point).export()))

print(io.recv())
io.close()
