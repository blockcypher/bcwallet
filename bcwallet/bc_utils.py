from bitmerchant.network import (BitcoinMainNet, BitcoinTestNet,
        LitecoinMainNet, DogecoinMainNet, BlockCypherTestNet)

from bitmerchant.wallet import Wallet

from blockcypher.utils import (is_valid_coin_symbol, is_valid_hash,
        coin_symbol_from_mkey)

# collection of blockchain/crypto utilities and helper methods

COIN_SYMBOL_TO_BMERCHANT_NETWORK = {
        'btc': BitcoinMainNet,
        'btc-testnet': BitcoinTestNet,
        'ltc': LitecoinMainNet,
        'doge': DogecoinMainNet,
        'bcy': BlockCypherTestNet,
        }


def guess_network_from_mkey(mkey):
    cs = coin_symbol_from_mkey(mkey)
    return COIN_SYMBOL_TO_BMERCHANT_NETWORK.get(cs)


def get_tx_url(tx_hash, coin_symbol):
    assert is_valid_coin_symbol(coin_symbol), coin_symbol
    assert is_valid_hash(tx_hash), tx_hash
    return 'https://live.blockcypher.com/%s/tx/%s/' % (coin_symbol, tx_hash)


def verify_and_fill_address_paths_from_bip32key(address_paths, master_key, network=BitcoinMainNet):
    '''
    Take address paths and verifies their accuracy client-side.

    Also fills in all the available metadata (WIF, public key, etc)
    '''
    wallet_obj = Wallet.deserialize(master_key, network=network)

    address_paths_cleaned = []

    for address_path in address_paths:
        path = address_path['path']
        input_address = address_path['address']
        child_wallet = wallet_obj.get_child_for_path(path)

        if child_wallet.to_address() != input_address:
            err_msg = 'Client Side Verification Fail for %s on %s:\n%s != %s' % (
                    path,
                    master_key,
                    child_wallet.to_address(),
                    input_address,
                    )
            raise Exception(err_msg)

        pubkeyhex = child_wallet.get_public_key_hex(compressed=True)

        server_pubkeyhex = address_path.get('public')
        if server_pubkeyhex and server_pubkeyhex != pubkeyhex:
            err_msg = 'Client Side Verification Fail for %s on %s:\n%s != %s' % (
                    path,
                    master_key,
                    pubkeyhex,
                    server_pubkeyhex,
                    )
            raise Exception(err_msg)

        address_path_cleaned = {
            'pub_address': input_address,
            'path': path,
            'pubkeyhex': pubkeyhex,
            }

        if child_wallet.private_key:
            privkeyhex = child_wallet.get_public_key_hex(compressed=True)
            address_path_cleaned['wif'] = child_wallet.export_to_wif()
            address_path_cleaned['privkeyhex'] = privkeyhex
        address_paths_cleaned.append(address_path_cleaned)

    return address_paths_cleaned


def find_hexkeypairs_from_bip32key_bc(pub_address_list, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Given a bip32 master (extended) key, traverse both internal and external
    paths to `depth` looking for keys matching pub_address_list. In blockcypher parlance,
    this is checking subchain_indexes == (0, 1)

    This does not use the bip32 default wallet layout as that requires a
    hardened child wallet, which necesitates the private key or complicated
    management of multiple extended public keys.

    `pub_address_list` looks like this for BTC: ['1abc123...', '1def456...']
    `master_key` looks like this for BTC: xpriv123abc (or xpub123abc)

    Returns a dict of:
      - pub_address (supplied in pub_address_list)
      - privkeyhex
      - pubkeyhex
      - path
      - wif

    Which can be used directly in TX signing.
    If extended_key is a public key then method returns no privkeyhex
    and cannot be used TX signing.
    '''

    # FIXME: deal with circular imports (depends on where this code ends up)
    # defensive check:
    # assert is_valid_address(pub_address), pub_address

    pub_address_set = set(pub_address_list)
    wallet_obj = Wallet.deserialize(master_key, network=network)
    external_chain_wallet = wallet_obj.get_child(0)  # m/0
    internal_chain_wallet = wallet_obj.get_child(1)  # m/1

    # traverse path
    hexkeypair_dict_list = []
    for x in range(starting_pos, starting_pos+depth+1):
        external_path = "m/0/%d" % x
        internal_path = "m/1/%d" % x
        external_child = external_chain_wallet.get_child(x)
        internal_child = internal_chain_wallet.get_child(x)
        if external_child.to_address() in pub_address_set:
            if external_child.private_key:
                privkeyhex = external_child.private_key.get_key()
                wif = external_child.export_to_wif()
            else:
                privkeyhex = None
                wif = None
            hexkeypair_dict_list.append({
                'pub_address': external_child.to_address(),
                'privkeyhex': privkeyhex,
                'pubkeyhex': external_child.public_key.get_key(compressed=True),
                'path': external_path,
                'wif': wif,
                })
        if internal_child.to_address() in pub_address_set:
            if internal_child.private_key:
                privkeyhex = internal_child.private_key.get_key()
                wif = internal_child.export_to_wif()
            else:
                privkeyhex = None
                wif = None
            hexkeypair_dict_list.append({
                'pub_address': internal_child.to_address(),
                'privkeyhex': privkeyhex,
                'pubkeyhex': internal_child.public_key.get_key(compressed=True),
                'path': internal_path,
                'wif': wif,
                })

        # stop looking when all keypairs found
        if len(hexkeypair_dict_list) == len(pub_address_list):
            break

    return hexkeypair_dict_list


def find_hexkeypairs_from_bip32key_linear(pub_address_list, master_key,
        network=BitcoinMainNet, starting_pos=0, depth=100):
    '''
    Given a bip32 master (extended) key, traverse linearly to `depth` looking
    for a matching key.

    So it would go through m/0, m/1, m/2, m/3, etc.
    This path is not used in bcwallet.

    `pub_address_list` looks like this for BTC: ['1abc123...', '1def456...']
    `master_key` looks like this for BTC: xpriv123abc (or xpub123abc)

    Returns a dict of:
      - pub_address (supplied in pub_address_list)
      - privkeyhex
      - pubkeyhex
      - path
      - wif

    Which can be used directly in TX signing.
    If extended_key is a public key then method returns no privkeyhex
    and cannot be used TX signing.

    Note that the returned dictionary
    '''

    pub_address_set = set(pub_address_list)

    # FIXME: deal with circular imports (depends on where this code ends up)
    # defensive check:
    # assert is_valid_address(pub_address), pub_address

    wallet_obj = Wallet.deserialize(master_key, network=network)

    hexkeypair_dict_list = []
    # traverse path
    for x in range(starting_pos, starting_pos+depth+1):
        path = "m/%d" % x
        child = wallet_obj.get_child_for_path(path)
        if child.to_address() in pub_address_set:
            if wallet_obj.private_key:
                privkeyhex = child.private_key.get_key()
                wif = child.export_to_wif()
            else:
                privkeyhex = None
                wif = None
            hexkeypair_dict_list.append({
                'pub_address': child.to_address(),
                'privkeyhex': privkeyhex,
                'pubkeyhex': child.public_key.get_key(compressed=True),
                'path': path,
                'wif': wif,
                })

        # stop looking when all keypairs found
        if len(hexkeypair_dict_list) == len(pub_address_list):
            break

    return hexkeypair_dict_list


def hexkeypair_list_to_dict(hexkeypair_list):
    hexkeypair_dict = {}
    for hexkeypair in hexkeypair_list:
        pub_address = hexkeypair['pub_address']
        hexkeypair.pop('pub_address')
        hexkeypair_dict[pub_address] = hexkeypair
    return hexkeypair_dict
