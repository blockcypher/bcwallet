Bmoney is still under development and not ready for production use. You could very well lose money. Use at your own risk.

To install (alpha, for developers only):
```
$ git clone https://github.com/blockcypher/bmoney.git`
$ virtualenv --python=python2 venv  # see python2 note below 
$ . venv/bin/activate
$ pip install --editable .
```

pypi support to follow when bmoney is ready for primetime.

While python3 is great, this app is designed to work with python2 and is not tested for python3. There are a few reasons why python 2 is better in this case:
- The click library [strongly recommends python2 for command line apps](http://click.pocoo.org/4/python3/)
- Most operating systems comes with python2 pre-installed, not python3.
