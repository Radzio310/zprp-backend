# generate_keys.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 1) Wygeneruj klucz prywatny 2048‑bitowy
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# 2) Zapisz go w formacie PEM
priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
with open("private.pem", "wb") as f:
    f.write(priv_pem)

# 3) Wyciągnij i zapisz publiczny klucz
public_key = private_key.public_key()
pub_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
with open("public.pem", "wb") as f:
    f.write(pub_pem)

print("Wygenerowano private.pem i public.pem")
