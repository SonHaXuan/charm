from charm.toolbox.pairinggroup import PairingGroup, GT, G1, G2, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin

# Step 1: Setup pairing group and IBE scheme
group = PairingGroup('SS512')
ibe = IBE_BonehFranklin(group)
(pk, mk) = ibe.setup()

# Step 2: Generate small random seed and derive symmetric key
import os
seed = os.urandom(4)  # Just 4 bytes seed
# Use pairing to create GT element: e(g1, g2) where g1, g2 are derived from seed
g1_seed = group.hash(seed, G1)
g2_seed = group.hash(seed, G2)
sym_key = pair(g1_seed, g2_seed)  # This gives us a GT element

# Step 3: Encrypt seed using IBE with an identity string
id_str = "alice@example.com"
sk_id = ibe.extract(mk, id_str)
ciphertext_ibe = ibe.encrypt(pk, id_str, seed)
print("IBE ciphertext:", ciphertext_ibe)
# Step 4: Encrypt actual message with symmetric key using AES
message = b"Hello from Charm-Crypto!"
key_bytes = objectToBytes(sym_key, group)
sym_cipher = SymmetricCryptoAbstraction(key_bytes)
ciphertext_sym = sym_cipher.encrypt(message)

# ---------- Receiver Side ----------

# Step 5: Decrypt seed using IBE and reconstruct symmetric key
decrypted_seed = ibe.decrypt(pk, sk_id, ciphertext_ibe)
if decrypted_seed is None:
    print("IBE decryption failed!")
    exit(1)
    
# Reconstruct the same GT element from decrypted seed
g1_seed = group.hash(decrypted_seed, G1)
g2_seed = group.hash(decrypted_seed, G2)
decrypted_sym_key = pair(g1_seed, g2_seed)
decrypted_key_bytes = objectToBytes(decrypted_sym_key, group)
sym_cipher_recv = SymmetricCryptoAbstraction(decrypted_key_bytes)

# Step 6: Decrypt actual message
plaintext = sym_cipher_recv.decrypt(ciphertext_sym)

# Final output
print("Original message:", message)
print("Decrypted message:", plaintext)
print("Success:", message == plaintext)
