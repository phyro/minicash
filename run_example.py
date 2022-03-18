# Don't trust me with cryptography.

from wallet import Wallet


SERVER_ENDPOINT = "http://localhost:5000"
wallet = Wallet(SERVER_ENDPOINT)
wallet.status()

# Mint a proof of promise. We obtain a proof for 64 coins
proof = wallet.mint()
wallet.status()

# Error: We try to split by amount higher than available
fst_proofs, snd_proofs = wallet.split([proof], 65)
assert fst_proofs == []
assert snd_proofs == []
wallet.status()

# Error: We try to double-spend by providing a valid proof twice
fst_proofs, snd_proofs = wallet.split([proof, proof], 20)
assert fst_proofs == []
assert snd_proofs == []
wallet.status()

fst_proofs, snd_proofs = wallet.split([proof], 20)
# we expect 44 and 20 -> [4, 8, 32], [4, 16]
print(fst_proofs)
print(snd_proofs)
wallet.status()

fst_proofs2, snd_proofs2 = wallet.split(snd_proofs, 5)
# we expect 15 and 5 -> [1, 2, 4, 8], [1, 4]
print(fst_proofs2)
print(snd_proofs2)
wallet.status()

# Error: We try to double-spend and it fails
fst_proofs2, snd_proofs2 = wallet.split(snd_proofs, 5)
assert fst_proofs2 == []
assert snd_proofs2 == []
wallet.status()

# We expect to have proofs for amounts [1, 1, 2, 4, 4, 4, 8, 8, 32]
assert wallet.proof_amounts() == [1, 1, 2, 4, 4, 4, 8, 8, 32]