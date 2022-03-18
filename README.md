# Minicash

**The author is NOT a cryptographer and has not tested the libraries used or the code nor has anyone reviewed the work.
This means it's very likely a fatal flaw somewhere. This is meant only as educational and is not production ready.**

Minimal implementation of ecash based on David Wagner's variant of Chaumian blinding as described [on this cypherpunk mailing list post](http://cypherpunks.venona.com/date/1996/03/msg01848.html). Some implementation details follow [this description](https://gist.github.com/phyro/935badc682057f418842c72961cf096c).

First install the dependencies [ecc-pycrypto](https://github.com/lc6chang/ecc-pycrypto), [flask](https://flask.palletsprojects.com/en/2.0.x/) and [requests](https://docs.python-requests.org/en/latest/).

Requests and Flask can be installed with
```
pip3 install -r requirements.txt
```
For ecc-pycrypto, please visit https://github.com/lc6chang/ecc-pycrypto and follow installation instructions.

To test this, you need to run the server first. This is done by running `flask run`.
Example of interaction is in run_example.py and can be tested with `python3 run_example.py`.

The API contains only three endpoints:
* `/keys` - used to communicate the public keys for each amount variant.
* `/mint` - used for minting new coins. It returns a promise for 64 coins.
* `/split` - consumes proofs of promise and creates new promises based on the split amount.

**_NOTE: A serious implementation should at least include wallet level locking to avoid race conditioning updates as well as atomic guarantees in the split function._**