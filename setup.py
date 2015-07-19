# https://youtu.be/kNke39OZ2k0?t=65

from setuptools import setup

setup(
        name='bmoney',
        version='0.0.1',
        py_modules=['bmoney'],
        install_requires=[
            'click==4.1',
            'blockcypher==1.0.4',
            'bitmerchant==0.1.5',
            ],
        entry_points='''
            [console_scripts]
            bmoney=bmoney:cli
        '''
        )
