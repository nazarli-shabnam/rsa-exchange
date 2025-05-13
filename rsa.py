import random
from math import gcd
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def generate_rsa_keys():
    primes = [x for x in range(10, 100) if is_prime(x)]
    p = random.choice(primes)
    q = random.choice([x for x in primes if x != p])

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1:
        e += 2

    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt_rsa(plaintext, public_key):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def decrypt_rsa(ciphertext, private_key):
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext


public_key, private_key = generate_rsa_keys()
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}\n")
message = "HELLO"
print(f"Original Message: {message}")
encrypted = encrypt_rsa(message, public_key)
print(f"Encrypted Message: {encrypted}")
decrypted = decrypt_rsa(encrypted, private_key)
print(f"Decrypted Message: {decrypted}")