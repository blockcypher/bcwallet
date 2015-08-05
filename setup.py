# https://youtu.be/kNke39OZ2k0?t=65

from setuptools import setup

setup(
        name='bwallet',
        version='1.0.13',
        description='Simple BIP32 HD cryptocurrecy command line wallet',
        author='Michael Flaxman',
        author_email='mflaxman+blockcypher@gmail.com',
        url='https://github.com/blockcypher/bwallet/',
        py_modules=['bwallet'],
        install_requires=[
            'clint==0.4.1',
            'blockcypher==1.0.15',
            'bitmerchant==0.1.7',
            ],
        entry_points='''
            [console_scripts]
            bwallet=bwallet:invoke_cli
        ''',
        packages=['bwallet'],
        )
