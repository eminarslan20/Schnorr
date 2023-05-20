import hashlib
import random

# Sabitler
p = 2147483647  # Bir asal sayı seçin (p = 2q + 1, q asal olmalıdır)
q = 1073741823  # p'nin bir asal böleni
g = 2  # 1 < g < p

# Özel anahtar oluşturma
def generate_private_key():
    return random.randint(1, q)

# Genel anahtar oluşturma
def generate_public_key(private_key):
    return pow(g, private_key, p)

# İmza oluşturma
def generate_signature(message, private_key):
    k = random.randint(1, q)
    r = pow(g, k, p) % q

    message_hash = hashlib.sha256(message.encode()).digest()
    e = int.from_bytes(message_hash, byteorder='big')
    s = (k - private_key * r) % q

    return r, s

# İmza doğrulama
def verify_signature(message, signature, public_key):
    r, s = signature

    if r < 1 or r > q or s < 1 or s > q:
        return False

    message_hash = hashlib.sha256(message.encode()).digest()
    e = int.from_bytes(message_hash, byteorder='big')
    v = pow(g, s, p) * pow(public_key, r, p) % p % q

    return v == r

# Örnek kullanım
private_key = generate_private_key()
public_key = generate_public_key(private_key)
message = input("Şifrelenecek metni giriniz....:")

signature = generate_signature(message, private_key)
valid = verify_signature(message, signature, public_key)

print("Şifrelenmiş Anahtar:", private_key)
print("Açık Anahtar:", public_key)
print("İmza", signature)
print("İmzanın geçerliliği:", valid)
