bcwallet is still under development and not ready for production use. Use at your own risk.

To get started:
PIP INSTALATTION TEMPORARILY DISABLED, WILL BE BACK SOON
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

While python3 is great, this app is designed to work with python2 only. There are a few reasons why python 2 is better in this case:
- Most operating systems comes with python2 pre-installed, not python3.
- Python3 unicode handling causes problems, [Armin Ronacher strongly recommends python2 for command line apps](http://click.pocoo.org/4/python3/)

This wallet is built using:
- BlockCypher's very powerful [bitcoin API](https://github.com/sbuss). It supports features that other APIs don't, and not only makes this wallet possible but massively reduces the amount of client-side code written.
- Steven Buss' very awesome [bitmerchant](https://github.com/sbuss) library for generating keys
- Vitalik Buterin's [pybitcointools](https://bootstrap.pypa.io/get-pip.py) for ecdsa signatures and decoding raw bitcoin transactions
