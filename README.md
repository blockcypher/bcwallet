bwallet is still under development and not ready for production use. You could very well lose money. Use at your own risk.

pypi support to follow when bwallet is ready for primetime and will work as follows:
```
$ virtualenv --python=python2 venv  # see python2 note below 
$ . venv/bin/activate
$ pip install bwallet
$ bwallet
```
Note: the virtualenv (first 2 steps) shouldn't be strictly necessary,
but one of the dependency libraries requires a virtualenv to `pip install`.
Once that's fixed I'll update this.

To edit and submit a pull request:
```
$ git clone https://github.com/blockcypher/bwallet.git
$ cd bwallet
$ virtualenv --python=python2 venv  # see python2 note below 
$ . venv/bin/activate
$ pip install --editable .
$ bwallet
```

While python3 is great, this app is designed to work with python2 only. There are a few reasons why python 2 is better in this case:
- Most operating systems comes with python2 pre-installed, not python3.
- Python3 unicode handling causes problems, [Armin Ronacher strongly recommends python2 for command line apps](http://click.pocoo.org/4/python3/)

This wallet is built using:
- Steven Buss' very awesome [bitmerchant](https://github.com/sbuss) library for generating keys
- Vitalik Buterin's [https://github.com/vbuterin/pybitcointools](pybitcointools) for ecdsa signatures and decoding raw bitcoin transactions
