# Don't trust me with cryptography.

from wallet import Wallet


def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        f()
        raise Exception(f"Call didn't fail with {msg} when it should've.")
    except Exception as exc:
        assert exc.args[0] == msg

def assert_amt(proofs, expected):
    """Assert amounts the proofs contain."""
    assert [p["amount"] for p in proofs] == expected


SERVER_ENDPOINT = "http://localhost:5000"
wallet = Wallet(SERVER_ENDPOINT)
wallet.status()

# Mint a proof of promise. We obtain a proof for 64 coins
proof = wallet.mint()
wallet.status()

# Error: We try to split by amount higher than available
assert_err(
    lambda: wallet.split([proof], 65),
    "Split amount is higher than the total sum"
)
wallet.status()

# Error: We try to double-spend by providing a valid proof twice
assert_err(
    lambda: wallet.split([proof, proof], 20),
    "Duplicate proofs or promises."
)
wallet.status()

# OK: Split a proof by amount 20
fst_proofs, snd_proofs = wallet.split([proof], 20)
# we expect 44 and 20 -> [4, 8, 32], [4, 16]
assert_amt(fst_proofs, [4, 8, 32])
assert_amt(snd_proofs, [4, 16])
wallet.status()

# OK: Now split the 2nd proofs [4, 16] by 5
fst_proofs2, snd_proofs2 = wallet.split(snd_proofs, 5)
# we expect 15 and 5 -> [1, 2, 4, 8], [1, 4]
assert_amt(fst_proofs2, [1, 2, 4, 8])
assert_amt(snd_proofs2, [1, 4])
wallet.status()

# Error: We try to double-spend and it fails
double_spent_secret = snd_proofs[0]["secret_msg"]
assert_err(
    lambda: wallet.split(snd_proofs, 5),
    f"Already spent. Secret msg:{double_spent_secret}"
)
wallet.status()

# We expect to have proofs for amounts [1, 1, 2, 4, 4, 4, 8, 8, 32]
assert wallet.proof_amounts() == [1, 1, 2, 4, 4, 4, 8, 8, 32]

# Error: Try to inflate with a negative split. Take proofs [1, 4] and split by -500
assert_err(
    lambda: wallet.split(snd_proofs2, -500),
    "Invalid split amount: -500"
)
wallet.status()
assert wallet.proof_amounts() == [1, 1, 2, 4, 4, 4, 8, 8, 32]

# TODO: Add more tests
# Error: Try to change the proof amount
# Error: Modify curve point to something that wasn't signed by the ledger
# Error: Try to use negative amounts in proofs or outputs
