# brillouin

500 points, Crypto

## Description
brillouin is an exciting new b l o c c c h a i n authentication provider. you can tell how decentralized it is because the signatures are so small! nc crypto.chal.csaw.io 1004

Author: (@japesinator, @trailofbits)

Files: [brillouin.py](brillouin.py)

## Solution

Basic inspection of the file reveals that BLS Signature Scheme is used to sign and verify here. Googling here and there reveal
that it makes use of a function `e` called bilinear pairing function. It works on a pair of points on some elliptic curve and 
returns a point on some other curve. It has a property that - 

```
e(x + y, z) = e(x, z) * e(y, z)
```

We don't need to know the actual structure of the function, just this property is enough.

In BLS scheme, secret key `sk` is some integer and public key is the point `sk * g` where `g` is the generator of the curve.

We sign a message `m` by first hashing this message to some point using a hash function `H` and then multiplying it with our 
secret key `sk`:

`signature = sk * hash(m)`

We verify a message by comparing the values `e(g, signature)` and `e(pk, hash(m))`, the signature is valid if both of them 
evaluate to the same point.

```
if e(g, signature) == e(pk, hash(m)):
    print("signature is valid")
```

Why is this correct? Because for a valid signature:

`e(g, signature) = e(g, sk * hash(m)) = e(g, hash(m)) * e(g, hash(m)) * e(g, hash(m)) ....` (`sk` times)  
` = e(g * sk, hash(m)) = e(pk, hash(m))`

In BLS signature scheme we also have a concept called aggregation which is basically a linear operation over the public keys/ 
signatures. Coefficients are determined by the `lagrange_basis` function. Aggregation is used in multiparty signature schemes,
details of which I would be skipping, but you may read over [here]()

Now for the challenge, lets collect what all we have; We have three public keys `pA`, `pB` and `pC`. We can get message "ham"
signed by `pA`, `pB` is good for nothing and `pC` is the most useful - we can get any of our message signed. End goal - we 
need to give them three public keys `p1`, `p2` and `p3` and two signatures `s1` and `s2` such that aggregation of `s1` and `s2`
is a valid signature of the public key obtained by aggregation of `p1`, `p2` and `p3` for the message "this stuff".

There are some constraints too - `s1` and `s2` cannot be same ([here](brillouin.py#L65)), `p1` and `p2` must be one of the `pA`, 
`pB` and `pC`, though they can be same ([here](brillouin.py#L51)). _We have no limitations for `p2`_. This is our catch. We use
`lagrange_basis` function to calculate the coefficients -

```python
