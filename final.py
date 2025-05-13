import random
from math import gcd

#is prime
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

#private key math(modular inverse of a modulo m)
def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

#make RSA public and private keys
def generate_keys():
    primes = [i for i in range(10, 100) if is_prime(i)]
    p = random.choice(primes)
    q = random.choice([x for x in primes if x != p])
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1:
        e += 2

    d = modinv(e, phi)
    return ((e, n), (d, n))

#RSA encryption:each character is encrypted with public key
def rsa_encrypt(text, key):
    e, n = key
    return [pow(ord(char), e, n) for char in text]

#RSA decryption:each character is decrypted with private key
def rsa_decrypt(cipher, key):
    d, n = key
    return ''.join([chr(pow(c, d, n)) for c in cipher])

#encryption
def caesar_encrypt(text, key):
    encrypted = ''
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift + key) % 26 + shift)
        else:
            encrypted += char
    return encrypted

#decryption
def caesar_decrypt(cipher, key):
    return caesar_encrypt(cipher, -key)

class KDCServer:
    def __init__(self):
        self.users = {}  #to store users and their keys

    #registers a new user with generated RSA keys
    def register_user(self, username):
        public_key, private_key = generate_keys()
        self.users[username] = {
            'public_key': public_key,
            'private_key': private_key
        }
        return public_key

    #user's public key
    def get_public_key(self, username):
        return self.users.get(username, {}).get('public_key', None)

    #a random Caesar cipher key (between 1 and 25)
    def generate_cesar_key(self):
        return random.randint(1, 25)

    #distributes a Caesar cipher key encrypted with receiver's public RSA key
    def distribute_cesar_key(self, sender, receiver):
        cesar_key = str(self.generate_cesar_key())
        receiver_pubkey = self.get_public_key(receiver)
        encrypted_key = rsa_encrypt(cesar_key, receiver_pubkey)
        return encrypted_key

    #decrypts a received encrypted Caesar key using user's private key
    def decrypt_received_key(self, user, encrypted_key):
        return rsa_decrypt(encrypted_key, self.users[user]['private_key'])

kdc = KDCServer()

#user Register (as in the task)
bob_pub = kdc.register_user("Bob")
mehmet_pub = kdc.register_user("Mehmet")

#Bob requests to send a Caesar session key to Mehmet
encrypted_session_key = kdc.distribute_cesar_key("Bob", "Mehmet")
print(f"Encrypted session key sent to Mehmet: {encrypted_session_key}")

#Mehmet decrypts the Caesar session key
decrypted_key = kdc.decrypt_received_key("Mehmet", encrypted_session_key)
print(f"Mehmet decrypted session key: {decrypted_key}")

#Bob encrypts a message using Caesar cipher with the session key
message = "HELLO Mehmet"
caesar_key = int(decrypted_key)  #Bob and Mehmet now both know the key
encrypted_message = caesar_encrypt(message, caesar_key)
print(f"Bob sends encrypted Caesar message: {encrypted_message}")

#Mehmet decrypts the Caesar cipher message
original_message = caesar_decrypt(encrypted_message, caesar_key)
print(f"Mehmet decrypts message: {original_message}")
