# Don't trust me with cryptography.

"""
Implementation of https://gist.github.com/phyro/935badc682057f418842c72961cf096c
"""

import hashlib

from ecc.curve import secp256k1, Point
from ecc.key import gen_keypair

import b_dhke


class Ledger:
    def __init__(self, secret_key):
        self.master_key = secret_key
        self.used_proofs = set()  # no promise proofs have been used
        self.keys = self._derive_keys(self.master_key)

    @staticmethod
    def _derive_keys(master_key):
        """Deterministic derivation of keys for 2^n values."""
        return {
            2**i: int(hashlib.sha256((str(master_key) + str(i)).encode("utf-8")).hexdigest().encode("utf-8"), 16)
            for i in range(20)
        }

    def _generate_promises(self, amounts, B_s):
        """Generates promises that sum to the given amount."""
        return [
            self._generate_promise(amount, Point(B_["x"], B_["y"], secp256k1))
            for (amount, B_) in zip(amounts, B_s)
        ]

    def _generate_promise(self, amount, B_):
        """Generates a promise for given amount and returns a pair (amount, C')."""
        secret_key = self.keys[amount] # Get the correct key
        return {"amount": amount, "C'": b_dhke.step2_alice(B_, secret_key)}

    def _verify_proof(self, proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if proof["secret_msg"] in self.used_proofs:
            raise Exception("Already spent. Secret msg:{}".format(proof["secret_msg"]))
        secret_key = self.keys[proof["amount"]] # Get the correct key to check against
        C = Point(proof["C"]["x"], proof["C"]["y"], secp256k1)
        return b_dhke.verify(secret_key, C, proof["secret_msg"])

    def _verify_outputs(self, total, amount, output_data):
        """Verifies the expected split was correctly computed"""
        fst_amt, snd_amt = total-amount, amount  # we have two amounts to split to
        fst_outputs = self._get_output_split(fst_amt)
        snd_outputs = self._get_output_split(snd_amt)
        expected = fst_outputs + snd_outputs
        given = [o["amount"] for o in output_data]
        return given == expected
    
    def _verify_no_duplicates(self, proofs, output_data):
        secret_msgs = [p["secret_msg"] for p in proofs]
        if len(secret_msgs) != len(list(set(secret_msgs))):
            return False
        B_xs = [od["B'"]["x"] for od in output_data]
        if len(B_xs) != len(list(set(B_xs))):
            return False
        return True
    
    def _verify_split_amount(self, amount):
        """Split amount like output amount can't be negative or too big."""
        try:
            self._verify_amount(amount)
        except:
            # For better error message
            raise Exception("Invalid split amount: " + str(amount))
    
    @staticmethod
    def _verify_amount(amount):
        """Any amount used should be a positive integer not larger than 2^32."""
        valid = isinstance(amount, int) and amount > 0 and amount < 2**32
        if not valid:
            raise Exception("Invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(self, proofs, outs):
        """Verify that Σoutputs - Σinputs = 0."""
        sum_inputs = sum(self._verify_amount(p["amount"]) for p in proofs)
        sum_outputs = sum(self._verify_amount(p["amount"]) for p in outs)
        assert sum_outputs - sum_inputs == 0

    def _get_output_split(self, amount):
        """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
        self._verify_amount(amount)
        bits_amt = bin(amount)[::-1][:-2]
        rv = []
        for (pos, bit) in enumerate(bits_amt):
            if bit == "1":
                rv.append(2**pos)
        return rv

    # Public methods

    def get_pubkeys(self):
        """Returns public keys for possible amounts."""
        return {
            amt: self.keys[amt] * secp256k1.G
            for amt in [2**i for i in range(20)]
        }

    def mint(self, B_):
        """Mints a promise for 64 coins for B_."""
        # NOTE: This could be implemented that a mint requires a rare pow
        return self._generate_promise(64, B_)

    def split(self, proofs, amount, output_data):
        """Consumes proofs and prepares new promises based on the amount split."""
        self._verify_split_amount(amount)
        # Verify proofs are valid
        if not all([self._verify_proof(p) for p in proofs]):
            return False

        total = sum([p["amount"] for p in proofs])

        if not self._verify_no_duplicates(proofs, output_data):
            raise Exception("Duplicate proofs or promises.")
        if amount > total:
            raise Exception("Split amount is higher than the total sum")
        if not self._verify_outputs(total, amount, output_data):
            raise Exception("Split of promises is not as expected.")

        # Perform split
        proof_msgs = set([p["secret_msg"] for p in proofs])
        # Mark proofs as used and prepare new promises
        self.used_proofs |= proof_msgs
        outs_fst = self._get_output_split(total-amount)
        outs_snd = self._get_output_split(amount)
        B_fst = [od["B'"] for od in output_data[:len(outs_fst)]]
        B_snd = [od["B'"] for od in output_data[len(outs_fst):]]
        prom_fst, prom_snd = self._generate_promises(outs_fst, B_fst), self._generate_promises(outs_snd, B_snd)
        self._verify_equation_balanced(proofs, prom_fst + prom_snd)
        return prom_fst, prom_snd
