from bitmerchant.network import (BitcoinMainNet, BitcoinTestNet,
        LitecoinMainNet, DogecoinMainNet)

from bitmerchant.wallet import Wallet

from blockcypher.utils import is_valid_coin_symbol, is_valid_hash


# collection of helper methods
# some may be moved to either the bitmerchant or blockcypher libraries

# TODO: move to COIN_SYMBOL_ODICT_LIST once popping issue resolved in library
COIN_SYMBOL_LIST = ['btc', 'btc-testnet', 'ltc', 'doge', ]  # 'bcy']


# TODO: duplicated in blockcypher.constants?
FIRST4_MKEY_MAPPINGS = {
        # first4: [bitmerchant_network, blockcypher, coin_symbol]
        'XPRV': [BitcoinMainNet, 'btc'],
        'XPUB': [BitcoinMainNet, 'btc'],
        'TPRV': [BitcoinTestNet, 'btc-testnet'],
        'TPUB': [BitcoinTestNet, 'btc-testnet'],
        'LTPV': [LitecoinMainNet, 'ltc'],
        'LTUB': [LitecoinMainNet, 'ltc'],
        'DGPV': [DogecoinMainNet, 'doge'],
        'DGPV': [DogecoinMainNet, 'doge'],
        # 'BPRV': [BlockCypherTestNet, 'bcy'],
        # 'BPUB': [BlockCypherTestNet, 'bcy'],
        }

COIN_SYMBOL_TO_BMERCHANT_NETWORK = {}
for x in FIRST4_MKEY_MAPPINGS:
    network = FIRST4_MKEY_MAPPINGS[x][0]
    coin_symbol = FIRST4_MKEY_MAPPINGS[x][1]
    COIN_SYMBOL_TO_BMERCHANT_NETWORK[coin_symbol] = network


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


def get_tx_url(tx_hash, coin_symbol):
    assert is_valid_coin_symbol(coin_symbol), coin_symbol
    assert is_valid_hash(tx_hash), tx_hash
    return 'https://live.blockcypher.com/%s/tx/%s/' % (coin_symbol, tx_hash)


def find_hexkeypair_from_bip32key_bc(pub_address, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Given a bip32 master (extended) key, traverse both internal and external
    paths to `depth` looking for a matching key. In blockcypher parlance,
    this is checking subchain_indexes == (0, 1)

    This does not use the bip32 default wallet layout as that requires a
    hardened child wallet, which necesitates the private key or complicated
    management of multiple extended public keys.

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
    external_chain_wallet = wallet_obj.get_child(0)  # m/0
    internal_chain_wallet = wallet_obj.get_child(1)  # m/1

    # traverse path
    for x in range(starting_pos, starting_pos+depth+1):
        external_path = "m/0/%d" % x
        internal_path = "m/1/%d" % x
        external_child = external_chain_wallet.get_child(x)
        internal_child = internal_chain_wallet.get_child(x)
        if external_child.to_address() == pub_address:
            if external_child.private_key:
                privkeyhex = external_child.private_key.get_key()
            else:
                privkeyhex = None
            return {
                    'privkeyhex': privkeyhex,
                    'pubkeyhex': external_child.public_key.get_key(
                        compressed=True),
                    'path': external_path,
                    }
        if internal_child.to_address() == pub_address:
            if internal_child.private_key:
                privkeyhex = internal_child.private_key.get_key()
            else:
                privkeyhex = None
            return {
                    'privkeyhex': privkeyhex,
                    'pubkeyhex': internal_child.public_key.get_key(
                        compressed=True),
                    'path': internal_path,
                    }
    # No matches
    return {
            'privkeyhex': None,
            'pubkeyhex': None,
            'path': None,
            }

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


def find_hexkeypair_from_bip32key_linear(pub_address, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Given a bip32 master (extended) key, traverse linearly to `depth` looking
    for a matching key.

    So it would go through m/0, m/1, m/2, m/3, etc.
    This path is not used in bwallet.

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


def find_path_from_bip32key_bc(pub_address, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Especially useful when using extended public keys for the master key
    '''
    return find_hexkeypair_from_bip32key_bc(pub_address=pub_address,
            master_key=master_key, network=network, starting_pos=starting_pos,
            depth=depth)['path']


def find_paths_from_bip32key_bc(pub_address_list, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Bulk method for find_path_from_bip32masterkey

    # TODO: re-write this for massive speedup
    '''
    paths = []
    for pub_address in pub_address_list:
        path = find_path_from_bip32key_bc(
                pub_address=pub_address,
                master_key=master_key,
                network=network,
                starting_pos=starting_pos,
                depth=depth,
                )
        paths.append(path)
    return paths
