# Don't trust me with cryptography.

import random

import requests
from ecc.curve import secp256k1, Point
import b_dhke


class LedgerAPI:
    def __init__(self, url):
        self.url = url
        self.keys = self._get_keys(url)

    @staticmethod
    def _get_keys(url):
        resp = requests.get(url + '/keys').json()
        return {
            int(amt): Point(val["x"], val["y"], secp256k1)
            for amt, val in resp.items()
        }

    @staticmethod
    def _get_output_split(amount):
        """Given an amount returns a list of amounts returned e.g. 13 is [1, 4, 8]."""
        bits_amt = bin(amount)[::-1][:-2]
        rv = []
        for (pos, bit) in enumerate(bits_amt):
            if bit == "1":
                rv.append(2**pos)
        return rv
    
    def _construct_proofs(self, promises, secrets):
        """Returns proofs of promise from promises."""
        proofs = []
        for promise, (r, secret_msg) in zip(promises, secrets):
            C_ = Point(promise["C'"]["x"], promise["C'"]["y"], secp256k1)
            C = b_dhke.step3_bob(C_, r, self.keys[promise["amount"]])
            proofs.append({
                "amount": promise["amount"],
                "C": {
                    "x": C.x,
                    "y": C.y,
                },
                "secret_msg": secret_msg,
            })
        return proofs

    def mint(self):
        """Mints new coins and returns a proof of promise."""
        secret_msg = str(random.getrandbits(128))
        B_, r = b_dhke.step1_bob(secret_msg)
        promise = requests.post(self.url + "/mint", json={"x": str(B_.x), "y": str(B_.y)}).json()
        return self._construct_proofs([promise], [(r, secret_msg)])[0]

    def split(self, proofs, amount):
        """Consume proofs and create new promises based on amount split."""
        total = sum([p["amount"] for p in proofs])
        fst_amt, snd_amt = total-amount, amount
        fst_outputs = self._get_output_split(fst_amt)
        snd_outputs = self._get_output_split(snd_amt)

        secrets = []
        output_data = []
        for output_amt in fst_outputs + snd_outputs:
            secret_msg = str(random.getrandbits(128))
            B_, r = b_dhke.step1_bob(secret_msg)
            secrets.append((r, secret_msg))
            output_data.append({
                "amount": output_amt,
                "B'": {
                    "x": B_.x,
                    "y": B_.y,
                },
            })

        promises = requests.post(self.url + "/split", json={
            "proofs": proofs, "amount": amount, "output_data": output_data
        }).json()
        if "error" in promises:
            raise Exception(promises["error"])

        # Obtain proofs from promises
        fst_proofs = self._construct_proofs(promises["fst"], secrets[:len(promises["fst"])])
        snd_proofs = self._construct_proofs(promises["snd"], secrets[len(promises["fst"]):])

        return fst_proofs, snd_proofs


class Wallet(LedgerAPI):
    """Minimal wallet wrapper."""
    def __init__(self, url):
        super().__init__(url)
        self.proofs = []

    def mint(self):
        proof = super().mint()
        self.proofs.append(proof)
        return proof

    def split(self, proofs, amount):
        fst_proofs, snd_proofs = super().split(proofs, amount)
        used_secret_msgs = [p["secret_msg"] for p in proofs]
        self.proofs = list(filter(lambda p: p["secret_msg"] not in used_secret_msgs, self.proofs))
        self.proofs += fst_proofs + snd_proofs
        return fst_proofs, snd_proofs

    def balance(self):
        return sum(p["amount"] for p in self.proofs)

    def status(self):
        print("Balance: {}".format(self.balance()))

    def proof_amounts(self):
        return [p["amount"] for p in sorted(self.proofs, key=lambda p: p["amount"])]
