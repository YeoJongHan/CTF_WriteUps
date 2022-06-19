from Crypto.Util.number import getPrime, getRandomRange, bytes_to_long

FLAG = bytes_to_long(open("flag.txt", "rb").read())
N = FLAG.bit_length() + 2**7

m = sorted([ getPrime(N) for _ in range(5) ])
share = []

while ((m[1]*m[2]*m[3] < m[0]*m[3]*m[4]) and m[4]<m[3]):
	m[4] = getPrime(N)

M = m[1]*m[2]
alpha = getRandomRange(2, M)
k = 4

for i in range(k):
    s = (FLAG + alpha*m[0]) % m[i+1]
    share.append(s)

with open("out.txt", 'w') as f:
    f.write(f"Public (m0): {hex(m[0])}\n\n")

    for i in range(len(share)):
        f.write(f"Share {i} (s{i}, m{i+1}): ({hex(share[i])}, {hex(m[i+1])})\n")