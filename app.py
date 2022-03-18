# Don't trust me with cryptography.

import hashlib

from ecc.curve import secp256k1, Point
from flask import Flask, request

from ledger import Ledger

# Ledger pubkey
ledger = Ledger("supersecretprivatekey")

app = Flask(__name__)

@app.route("/keys")
def keys():
    return ledger.get_pubkeys()

@app.route("/mint", methods=["POST"])
def mint():
    x = int(request.json["x"])
    y = int(request.json["y"])
    B_ = Point(x, y, secp256k1)
    promise = ledger.mint(B_)
    return promise

@app.route("/split", methods=["POST"])
def split():
    proofs = request.json["proofs"]
    amount = request.json["amount"]
    output_data = request.json["output_data"]
    try:
        fst_promises, snd_promises = ledger.split(proofs, amount, output_data)
        return {"fst": fst_promises, "snd": snd_promises}
    except Exception as exc:
        return {"error": str(exc)}