# https://youtu.be/kNke39OZ2k0?t=65

from setuptools import setup

setup(
        name='bwallet',
        version='1.0.0',
        py_modules=['bwallet'],
        install_requires=[
            'clint==0.4.1',
            'blockcypher==1.0.14',
            'bitmerchant==0.1.6',
            ],
        entry_points='''
            [console_scripts]
            bwallet=bwallet:cli
        '''
        )
