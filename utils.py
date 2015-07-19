from bitmerchant.network import (BitcoinMainNet, BitcoinTestNet,
        LitecoinMainNet, DogecoinMainNet)

from bitmerchant.wallet import Wallet

from hashlib import sha256

# collection of helper methods that will probably be moved to either the
# bitmerchant or blockcypher libraries


FIRST4_MKEY_MAPPINGS = {
        # first4: [bitmerchant_network, blockcypher, coin_symbol]
        'XPRV': [BitcoinMainNet, 'btc'],
        'XPUB': [BitcoinMainNet, 'btc'],
        'TPRV': [BitcoinTestNet, 'btc-testnet'],
        'TPUB': [BitcoinTestNet, 'btc-testnet'],
        'LTPV': [LitecoinMainNet, 'ltc'],
        'LTUP': [LitecoinMainNet, 'ltc'],
        'DGPV': [DogecoinMainNet, 'doge'],
        'DGUP': [DogecoinMainNet, 'doge'],
        }


def guess_coin_from_mkey(mkey):
    '''
    returns a tuple of [network, coin_symbol]
    '''
    return FIRST4_MKEY_MAPPINGS.get(mkey[:4].upper(), [None, None])


def guess_network_from_mkey(mkey):
    return guess_coin_from_mkey(mkey)[0]


def guess_cs_from_mkey(mkey):
    '''
    See also coin_symbol_from_mkey in python library blockcypher.utils.py
    '''
    return str(guess_coin_from_mkey(mkey)[1])


def find_hexkeys_from_bip32masterkey(pub_address, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Given a bip32 master (extended) key, traverse both internal and external
    paths to `depth` looking for a matching key.

    `pub_address` looks like this for BTC: 1abc123...
    `master_key` looks like this for BTC: xpriv123abc (or xpub123abc)

    Returns a dict of:
      - privkeyhex
      - pubkeyhex
      - path

    Which can be used directly in TX signing.
    If extended_key is a public key then method returns no privkeyhex
    and cannot be used TX signing.
    '''

    # FIXME: deal with circular imports (depends on where this code ends up)
    # defensive check:
    # assert is_valid_address(pub_address), pub_address

    wallet_obj = Wallet.deserialize(master_key, network=network)

    # traverse path
    for x in range(starting_pos, starting_pos+depth+1):
        path = "m/%d" % x
        child = wallet_obj.get_child_for_path(path)
        if child.to_address() == pub_address:
            if wallet_obj.private_key:
                privkeyhex = child.private_key.get_key()
            else:
                privkeyhex = None
            return {
                    'privkeyhex': privkeyhex,
                    'pubkeyhex': child.public_key.get_key(compressed=True),
                    'path': path,
                    }
    # No matches
    return {
            'privkeyhex': None,
            'pubkeyhex': None,
            'path': None,
            }


def find_hexkeys_from_bip32masterkey_standardpath(pub_address, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Given a bip32 master (extended) key, traverse both internal and external
    paths to `depth` looking for a matching key.

    `pub_address` looks like this for BTC: 1abc123...
    `master_key` looks like this for BTC: xpriv123abc (or xpub123abc)

    Returns a dict of:
      - privkeyhex
      - pubkeyhex
      - path

    Which can be used directly in TX signing.
    If extended_key is a public key then method returns no privkeyhex
    and cannot be used TX signing.
    '''

    # FIXME: deal with circular imports (depends on where this code ends up)
    # defensive check:
    # assert is_valid_address(pub_address), pub_address

    wallet_obj = Wallet.deserialize(master_key, network=network)

    # traverse internal and external path in fast order:
    for x in range(starting_pos, starting_pos+depth+1):
        int_path = "m/0/%d" % x
        ext_path = "m/1/%d" % x
        int_child = wallet_obj.get_child_for_path(int_path)
        ext_child = wallet_obj.get_child_for_path(ext_path)
        if int_child.to_address() == pub_address:
            if wallet_obj.private_key:
                privkeyhex = int_child.private_key.get_key()
            else:
                privkeyhex = None
            return {
                    'privkeyhex': privkeyhex,
                    'pubkeyhex': int_child.public_key.get_key(compressed=True),
                    'path': int_path,
                    }
        if ext_child.to_address() == pub_address:
            if wallet_obj.private_key:
                privkeyhex = ext_child.private_key.get_key()
            else:
                privkeyhex = None
            return {
                    'privkeyhex': privkeyhex,
                    'pubkeyhex': ext_child.public_key.get_key(compressed=True),
                    'path': ext_path,
                    }
    # No matches
    return {
            'privkeyhex': None,
            'pubkeyhex': None,
            'path': None,
            }


def find_path_from_bip32masterkey(pub_address, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Especially useful when using extended public keys for the master key
    '''
    return find_hexkeys_from_bip32masterkey(pub_address=pub_address,
            master_key=master_key, network=network, starting_pos=starting_pos,
            depth=depth)['path']


def find_paths_from_bip32masterkey(pub_address_list, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Bulk method for find_path_from_bip32masterkey
    '''
    paths = []
    for pub_address in pub_address_list:
        path = find_path_from_bip32masterkey(
                pub_address=pub_address,
                master_key=master_key,
                network=network,
                starting_pos=starting_pos,
                depth=depth,
                )
        paths.append(path)
    return paths


def get_blockcypher_walletname_from_mpub(mpub):
    '''
    Blockcypher limits wallet names to 25 chars.

    Hash the master pubkey and take the first 25 chars.
    '''
    assert type(mpub) in (str, unicode), mpub
    return sha256(mpub).hexdigest()[:25]
