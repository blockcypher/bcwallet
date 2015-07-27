# https://youtu.be/kNke39OZ2k0?t=65

from setuptools import setup

setup(
        name='bwallet',
        version='0.0.1',
        py_modules=['bwallet'],
        install_requires=[
            'click==4.1',
            'blockcypher==1.0.8',
            'bitmerchant==0.1.5',
            ],
        entry_points='''
            [console_scripts]
            bwallet=bwallet:cli
        '''
        )
