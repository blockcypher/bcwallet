# https://youtu.be/kNke39OZ2k0?t=65

from setuptools import setup

setup(
        name='bcwallet',
        version='1.2.3',
        description='Simple BIP32 HD cryptocurrecy command line wallet',
        author='Michael Flaxman',
        author_email='mflaxman+blockcypher@gmail.com',
        url='https://github.com/blockcypher/bcwallet/',
        py_modules=['bcwallet'],
        install_requires=[
            'clint==0.4.1',
            'blockcypher==1.0.53',
            'bitmerchant==0.1.8',
            'tzlocal==1.2',
            ],
        entry_points='''
            [console_scripts]
            bcwallet=bcwallet:invoke_cli
        ''',
        packages=['bcwallet'],
        )
