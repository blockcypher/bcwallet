bcwallet is still under development and not ready for production use. Use at your own risk.

### Currently, the management of traversing for unused adresses is a bit wonky. A change is coming shortly. We recommend not using bcwallet in the meantime.

# Installation

## PIP INSTALATTION TEMPORARILY DISABLED DURING NAME CHANGE, WILL BE BACK SOON.

To get started:
```
$ pip install bcwallet
$ bcwallet
```

# FAQs

*Q: There are a hundred wallets out there, what makes bcwallet unique?*

A: bcwallet is:
- Concise and easy to audit. Does not use the file system.
- Hard to mess up. As long as you don't give away or lose your master private key, everything else is simple. Guard your master private key however you like.
- Nearly trustless. See below for details.
- Powerful. Supports offline transaction signing, multiple crypto-currencies, automatically adjusts transaction fees for current market conditions, allows user to specify number of blocks until a transaction will (likely) confirm, adds user entropy on key generation in case of a compromised CSPRNG, and more.


Q: Why is an HD wallet important?

A: The best practice in bitcoin is to [use a new address for every transaction](https://bitcoin.org/en/protect-your-privacy) (including the change address your wallet when you send funds). This is for both personal/network privacy as well as clarity in determining who has paid you.

Addresses correspond to private keys and are free to create, but the private key used to create an address must be saved or those funds are lost forever. This creates a serious and difficult key management problem, as each transaction means you have to store a new key. If you backup your keypool today and then do a bunch of transactions tomorrow (which your wallet generates new keys for), those new keys will not be included in your original backup. You could have a diligent backup and still lose funds!

All of these problems are solved with HD wallets. Just backup your master private key once and you're set forever.

HD wallets are essential, and you really shouldn't use any wallet that isn't HD (<cough>blockchain.info</cough>). 

--

Q: Does blockcypher ever see my private keys?

A: No! We never see your private keys. Keys are generated locally, and transactions are signed locally as well.


Q: What bad things could happen if I use this wallet?

A: While blockcypher can't steal your funds, every wallet has a security/convenience tradeoff. Here are bcwallet's:
- Blockcypher has your extended public key and can easily use that to figure out which addresses you control, which is bad for your privacy. We don't ask for a name or email address to use the wallet, but unless you're connected to the internet using Tor we could see your IP address.
- Blockcypher could suffer from downtime, which would make bcwallet fairly worthless: you wouldn't be able to fetch your balance, transaction history, unspent transaction outputs, or broadcast transactions. However, you can always dump your private keys and addresses (using option 0 on the home screen) to spend your funds with *any* bitcoin wallet. If a wallet supported importing a master private key (hopefully more will in the future), you could just import that one string.
- Blockcypher could trick you into paying a large transaction fee (to whatever miner mined your transaction, not to blockcypher). Since bcwallet relies on blockcypher to fetch how much bitcoin each address controls (the UTXOs), if blockcypher were to under-report it could cause bcwallet to mis-calculate the transaction fee. Blockcypher has no incentive to do this of course, and was built to solve this very problem.

Q: What path for key derivation do you use? BIP32 default wallet layout? BIP39? BIP44?

A: We use a simple derivation with m/0/k for the external chain (receiving addresses) and m/1/k for the internal chain (change addresses). The BIP32 default wallet layout (not that commonly implemented) and BIP44 wallets both use hardened derivation for these chains, which means your master public key is completely useless, and one core feature of bcwallet is that you can boot the wallet using just an extended *public* key (very useful for airgapping and signing transactions offline). bcwallet's simplified choice of tree traversal also makes it much harder to lose funds by losing track of them during traversal. Since after the hardening BIP32 and BIP44 are almost identical implementations, we may add support for those wallets in the future, though thye'd have to be booted with the master private key (a master public key wouldn't be able to do hardened deriviation).


Q: Why is this this app designed to work with python2 only?

A: python3 is great, but but there are a few reasons why python 2 is better for this case:
- Most operating systems comes with python2 pre-installed, not python3.
- Python3 unicode handling causes problems, [Armin Ronacher strongly recommends python2 for command line apps](http://click.pocoo.org/4/python3/)
- 

Q: Can I submit a pull request to bcwallet?

A: Absolutely! If you'd like to edit bcwallet, here's a better way to install it on your machine:
```
$ git clone https://github.com/blockcypher/bcwallet.git
$ cd bcwallet
$ virtualenv --python=python2 venv  # see python2 note below 
$ . venv/bin/activate
$ pip install --editable .
$ bcwallet
```

# Acknowledgements

This wallet is built using:
- BlockCypher's very powerful [bitcoin API](http://www.blockcypher.com/). It supports features that other APIs don't, and not only makes this wallet possible but massively reduces the amount of client-side code written.
- Steven Buss' very awesome [bitmerchant](https://github.com/sbuss) library for generating keys
- Vitalik Buterin's [pybitcointools](https://bootstrap.pypa.io/get-pip.py) for ecdsa signatures and decoding raw bitcoin transactions
