bcwallet is still under development and not ready for production use. Use at your own risk.

# Installation

## PIP INSTALATTION TEMPORARILY DISABLED DURING NAME CHANGE, WILL BE BACK SOON.

To get started:
```
$ pip install bcwallet
$ bcwallet
```

If you'd like to edit bcwallet (say to submit a pull request):
```
$ git clone https://github.com/blockcypher/bcwallet.git
$ cd bcwallet
$ virtualenv --python=python2 venv  # see python2 note below 
$ . venv/bin/activate
$ pip install --editable .
$ bcwallet
```

# FAQs

Q: There are a hundred wallets out there, what makes bcwallet unique?
A: bcwallet is:
- Incredibly concise and designed to be easy to audit.
- Hard to mess up. As long as you don't lose or give away your master private key, everything else is simple. You can guard it however you like.
- Nearly trustless (see below for details).
- Powerful. Supports offline transaction signing, multiple crypto-currencies, always accruate transaction fees, and more.


Q: Why is an HD wallet important?
A: The best practice in bitcoin is to [use a new address for every transaction](https://bitcoin.org/en/protect-your-privacy) (including your change address). This is for both personal/network privacy as well as clarity. For personal privacy, using new addresses for each transaction means people you transact with can't see every transaction you make. For network privacy, using new addresses for each transaction people looking at activity on the bitcoin network can't easily deduce who is transaction with who. For clarity, if Alice is the only person who has ever been given address A, then any payment to address A must've been sent from Alice.

Addresses correspond to private keys and are free to create, but the private key used to create an address must be saved in order to later spend those funds. This creates a serious and difficult key-management problem, as each transaction means you have to store another key. If you backup your keypool today, do a bunch of transactions (and your wallet generates new keys for them) those new keys will not be included in your original backup. You could have diligent backups and still lose funds!

All of these problems are solved with HD wallets. Just backup your master private key once and you're set forever.

HD wallets are essential, and you really shouldn't use any wallet that isn't HD (<cough>blockchain.info</cough>). 


Q: What path for key derivation do you use? BIP32 default wallet? BIP44? BIP39?
A: We use a simple derivation with m/0/k for the external chain and m/1/k for the internal chain (change addresses). The BIP32 default wallet layout (not that common) and BIP44 wallets both use hardened derivation, which means your master public key is completely useless and this would make booting the wallet with an extended public key much more complicated. Since after the hardening BIP32 and BIP44 are fairly similar in implementation, we may add support for those wallets if booted with the master private key (a master public key wouldn't be able to do hardened deriviation).


Q: Could blockcypher steal my funds?
A: No! We never see your private keys. Keys are generated locally, and transactions are signed locally as well.


Q: What bad things could happen if I use this wallet?
A: While blockcypher can't steal your funds, every wallet has a security/convenience tradeoff. Here are bcwallet's:
- Blockcypher has your extended public key, and can use that to figure out which addresses you control, which is bad for your privacy. We don't ask for a name or email address, but unless you're connected to the internet using Tor we can see your IP address.
- Blockcypher could suffer from downtime, which would make bcwallet fairly worthless: you wouldn't be able to fetch your balance, transaction history, unspent transaction outputs, or broadcast transactions. However, you can always dump your private keys and addresses (using option 0) to spend your funds with any bitcoin wallet. If more wallets add extended key support in the future, you could even just use your master key to migrate away.
- Blockcypher could cause you to pay a large transaction fee (to whatever miner mined your transaction, not to blockcypher). Since bcwallet relies on blockcypher to tell it how much bitcoin each address controls, if blockcypher were to under-report it could cause bcwallet to mis-calculate the transaction fee. Blockcypher has no incentive to do this of course, and historically mining pools have returned excess transaction fees in very rare cases where users have made this mistake.

Q: Why is this this app designed to work with python2 only?
A: python3 is great, but but there are a few reasons why python 2 is better for this case:
- Most operating systems comes with python2 pre-installed, not python3.
- Python3 unicode handling causes problems, [Armin Ronacher strongly recommends python2 for command line apps](http://click.pocoo.org/4/python3/)

# Acknowledgements

This wallet is built using:
- BlockCypher's very powerful [bitcoin API](https://github.com/sbuss). It supports features that other APIs don't, and not only makes this wallet possible but massively reduces the amount of client-side code written.
- Steven Buss' very awesome [bitmerchant](https://github.com/sbuss) library for generating keys
- Vitalik Buterin's [pybitcointools](https://bootstrap.pypa.io/get-pip.py) for ecdsa signatures and decoding raw bitcoin transactions
