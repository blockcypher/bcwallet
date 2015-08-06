# -*- coding: utf-8 -*-

import sys
import argparse

# just for printing
from clint.textui import puts, colored, indent

from bitmerchant.wallet import Wallet

from blockcypher import (create_hd_wallet, get_wallet_details,
        create_unsigned_tx, verify_unsigned_tx, get_input_addresses,
        make_tx_signatures, broadcast_signed_transaction,
        get_blockchain_overview, get_total_balance)
from blockcypher.utils import (satoshis_to_btc, get_blockcypher_walletname_from_mpub,
        coin_symbol_from_mkey)
from blockcypher.constants import COIN_SYMBOL_MAPPINGS

from .bc_utils import (guess_network_from_mkey,
        find_hexkeypairs_from_bip32key_bc, get_tx_url, hexkeypair_list_to_dict,
        COIN_SYMBOL_TO_BMERCHANT_NETWORK)

from .cl_utils import (format_without_rounding, format_with_k_separator,
        debug_print, choice_prompt, get_crypto_address, get_wif_obj, get_int,
        confirm, get_user_entropy, coin_symbol_chooser, txn_preference_chooser,
        first4mprv_from_mpub, print_pubwallet_notice,
        print_bwallet_basic_priv_opening, print_bwallet_piped_priv_opening,
        print_bwallet_basic_pub_opening,
        BWALLET_PRIVPIPE_EXPLANATION, DEFAULT_PROMPT)


# Globals that can be overwritten at startup
VERBOSE_MODE = False
USER_ONLINE = False
BLOCKCYPHER_API_KEY = ''


def verbose_print(to_print):
    if VERBOSE_MODE:
        debug_print(to_print)


def get_public_wallet_url(mpub):
    # subchain indices set at 0 * 1
    return 'https://live.blockcypher.com/%s/xpub/%s/?subchain-indices=0-1' % (
            coin_symbol_from_mkey(mpub),
            mpub,
            )


def is_connected_to_blockcypher():
    try:
        get_blockchain_overview()
        return True
    except Exception as e:
        verbose_print(e)
        return False


def display_balance_info(wallet_obj, verbose=False):
    if not USER_ONLINE:
        return

    mpub = wallet_obj.serialize_b58(private=False)

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )

    verbose_print('Wallet Name: %s' % wallet_name)
    verbose_print('API Key: %s' % BLOCKCYPHER_API_KEY)

    coin_symbol = coin_symbol_from_mkey(mpub)

    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol,
            )
    verbose_print(wallet_details)

    currency_abbrev = COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev']
    puts('-' * 70 + '\n')
    puts(colored.green('Confirmed Received: %s satoshis (%s %s)' % (
        format_with_k_separator(wallet_details['total_received']),
        satoshis_to_btc(wallet_details['total_received']),
        currency_abbrev,
        )))
    puts(colored.green('Confirmed Sent: %s satoshis (%s %s)' % (
        format_with_k_separator(wallet_details['total_sent']),
        satoshis_to_btc(wallet_details['total_sent']),
        currency_abbrev,
        )))
    puts(colored.green('Confirmed Balance: %s satoshis (%s %s)' % (
        format_with_k_separator(wallet_details['balance']),
        satoshis_to_btc(wallet_details['balance']),
        currency_abbrev,
        )))
    tx_string = 'Confirmed Transactions: %s' % wallet_details['n_tx']
    if wallet_details['unconfirmed_n_tx']:
        tx_string += ' (+%s Unconfirmed)' % wallet_details['unconfirmed_n_tx']
    puts(colored.green(tx_string))

    puts(colored.blue('More info: %s\n' % get_public_wallet_url(mpub)))

    return wallet_details['final_balance']


def get_used_addresses(wallet_obj):
    '''
    Get addresses already used by the wallet
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )

    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol_from_mkey(mpub),
            )
    verbose_print(wallet_details)

    return set(wallet_details['wallet'].get('addresses', []))


def get_unused_addresses_on_subchain(wallet_obj, subchain_index,
        num_addrs_to_return, used_addr_set=set()):
    '''
    Traverse a subchain_index for unused addresses

    Returns a dict of the following form:
        {'address': '1abc123...', 'path': 'm/0/9',}
    '''
    assert type(subchain_index) is int, subchain_index

    subchain_wallet = wallet_obj.get_child(subchain_index)  # m/subchain_index

    attempt_cnt = 0
    addresses_found = []
    while True:
        addr = subchain_wallet.get_child(attempt_cnt).to_address()
        if addr not in used_addr_set:
            addresses_found.append({
                'address': addr,
                'path': 'm/%s/%s' % (subchain_index, attempt_cnt),
                })

        if len(addresses_found) >= num_addrs_to_return:
            break

        attempt_cnt += 1

    return addresses_found


def get_unused_receiving_addresses(wallet_obj, num_addrs_to_return=5):
    used_addr_set = get_used_addresses(wallet_obj=wallet_obj)
    return get_unused_addresses_on_subchain(
            wallet_obj=wallet_obj,
            subchain_index=0,  # external chain
            num_addrs_to_return=num_addrs_to_return,
            used_addr_set=used_addr_set,
            )


def get_unused_change_addresses(wallet_obj, num_addrs_to_return=1):
    used_addr_set = get_used_addresses(wallet_obj=wallet_obj)
    return get_unused_addresses_on_subchain(
            wallet_obj=wallet_obj,
            subchain_index=1,  # internal chain
            num_addrs_to_return=num_addrs_to_return,
            used_addr_set=used_addr_set,
            )


def display_new_receiving_addresses(wallet_obj):

    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to see which addresses have been used.'))
        puts(colored.red('You may dump all your addresses while offline by selecting option 0.'))
        return

    mpub = wallet_obj.serialize_b58(private=False)

    unused_receiving_addresses = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=5,
            )

    puts('-' * 70 + '\n')
    puts('Next 5 Unused %s Receiving Addresses (for people to send you funds):' %
            COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev']
            )

    for unused_receiving_address in unused_receiving_addresses:
        with indent(2):
            puts(colored.green('%s (path is %s)' % (
                unused_receiving_address['address'],
                unused_receiving_address['path'],
                )))


def display_recent_txs(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to find transactions related to your addresses.'))
        puts(colored.red('You may dump all your addresses while offline by selecting option 0.'))
        return

    # Show overall balance info
    display_balance_info(wallet_obj=wallet_obj)

    mpub = wallet_obj.serialize_b58(private=False)
    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )

    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol_from_mkey(mpub),
            )
    verbose_print(wallet_details)

    # TODO: pagination for lots of transactions
    if not wallet_details.get('txrefs'):
        puts('No Transactions')

    txs = wallet_details.get('unconfirmed_txrefs', []) \
            + wallet_details.get('txrefs', [])
    for tx in txs:
        # Logic copied from block explorer
        # templates/address_overview.html
        if tx.get('received'):
            tx_time = tx.get('received')
        else:
            tx_time = tx.get('confirmed')
        puts(colored.green('%s GMT: %s satoshis (%s %s) %s in TX hash %s' % (
            tx_time.strftime("%Y-%m-%d %H:%M"),
            format_with_k_separator(tx.get('value', 0)),
            format_without_rounding(satoshis_to_btc(tx.get('value', 0))),
            COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev'],
            'sent' if tx.get('tx_input_n') >= 0 else 'received',  # HACK!
            tx.get('tx_hash'),
            )))


def send_funds(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('Blockcypher connection needed to fetch unspents and broadcast signed transaction.'))
        puts(colored.red('You may dump all your addresses and private keys while offline by selecting option 0 on the home screen.'))
        return

    mpub = wallet_obj.serialize_b58(private=False)
    if not wallet_obj.private_key:
        print_pubwallet_notice(mpub=mpub)
        return

    coin_symbol = str(coin_symbol_from_mkey(mpub))
    verbose_print(coin_symbol)

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )
    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol,
            )
    verbose_print(wallet_details)

    if wallet_details['final_balance'] == 0:
        puts(colored.red("0 balance. You can't send funds if you don't have them!"))
        return

    mpriv = wallet_obj.serialize_b58(private=True)

    display_shortname = COIN_SYMBOL_MAPPINGS[coin_symbol]['display_shortname']
    puts('What %s address do you want to send to?' % display_shortname)
    destination_address = get_crypto_address(coin_symbol=coin_symbol)

    VALUE_PROMPT = 'Your current balance is %s (in satoshis). How much do you want to send? Note that due to transaction fees your full balance may not be available to send.' % (
            format_with_k_separator(wallet_details['final_balance']))
    puts(VALUE_PROMPT)
    dest_satoshis = get_int(
            max_int=wallet_details['final_balance'],
            user_prompt=DEFAULT_PROMPT,
            )

    inputs = [{
            'wallet_name': wallet_name,
            'wallet_token': BLOCKCYPHER_API_KEY,
            }, ]
    outputs = [{
            'value': dest_satoshis,
            'address': destination_address,
            }, ]

    change_address = get_unused_change_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=1,
            )[0]['address']

    tx_preference = txn_preference_chooser(
            user_prompt=DEFAULT_PROMPT,
            default_input='1',
            )

    verbose_print('Inputs:')
    verbose_print(inputs)
    verbose_print('Outputs:')
    verbose_print(outputs)
    verbose_print('Change Address: %s' % change_address)
    verbose_print('coin symbol: %s' % coin_symbol)
    verbose_print('TX Preference: %s' % tx_preference)

    unsigned_tx = create_unsigned_tx(
        inputs=inputs,
        outputs=outputs,
        change_address=change_address,
        preference=tx_preference,
        coin_symbol=coin_symbol,
        # will verify in the next step,
        # that way if there is an error here we can display that to user
        verify_tosigntx=False,
        include_tosigntx=True,
        )

    verbose_print('Unsigned TX:')
    verbose_print(unsigned_tx)

    if 'errors' in unsigned_tx:
        puts(colored.red('TX Error(s): Tx NOT Signed or Broadcast'))
        for error in unsigned_tx['errors']:
            puts(colored.red(error['error']))
        # Abandon
        return

    # Verify TX requested to sign is as expected
    tx_is_correct, err_msg = verify_unsigned_tx(
            unsigned_tx=unsigned_tx,
            inputs=inputs,
            outputs=outputs,
            sweep_funds=False,
            change_address=change_address,
            coin_symbol=coin_symbol,
            )
    if not tx_is_correct:
        puts(colored.red('TX Error: Tx NOT Signed or Broadcast'))
        puts(colored.red(err_msg))
        # Abandon
        return

    input_addresses = get_input_addresses(unsigned_tx)
    verbose_print('input_addresses')
    verbose_print(input_addresses)
    hexkeypair_list = find_hexkeypairs_from_bip32key_bc(
        pub_address_list=input_addresses,
        master_key=mpriv,
        network=guess_network_from_mkey(mpriv),
        starting_pos=0,
        depth=100,
        )
    verbose_print('hexkeypair_list:')
    verbose_print(hexkeypair_list)
    hexkeypair_dict = hexkeypair_list_to_dict(hexkeypair_list)

    if len(hexkeypair_dict.keys()) != len(input_addresses):
        notfound_addrs = set(input_addresses) - set(hexkeypair_dict.keys())
        err_msg = "Couldn't find %s traversing bip32 key" % notfound_addrs
        raise Exception('Traversal Fail: %s' % err_msg)

    privkeyhex_list = [hexkeypair_dict[x]['privkeyhex'] for x in input_addresses]
    pubkeyhex_list = [hexkeypair_dict[x]['pubkeyhex'] for x in input_addresses]

    verbose_print('Private Key List: %s' % privkeyhex_list)
    verbose_print('Public Key List: %s' % pubkeyhex_list)

    # sign locally
    tx_signatures = make_tx_signatures(
            txs_to_sign=unsigned_tx['tosign'],
            privkey_list=privkeyhex_list,
            pubkey_list=pubkeyhex_list,
            )
    verbose_print('TX Signatures: %s' % tx_signatures)

    # final confirmation before broadcast

    CONF_TEXT = 'Send %s satoshis (%s %s) to %s with a fee of %s satoshis (%s %s, or %s%% of the amount transacted)?' % (
            format_with_k_separator(dest_satoshis),
            format_without_rounding(satoshis_to_btc(dest_satoshis)),
            COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
            destination_address,
            unsigned_tx['tx']['fees'],
            format_without_rounding(satoshis_to_btc(unsigned_tx['tx']['fees'])),
            COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
            round(100.0 * unsigned_tx['tx']['fees'] / dest_satoshis, 4),
            )
    puts(CONF_TEXT)

    if not confirm(user_prompt=DEFAULT_PROMPT, default=True):
        puts(colored.red('Transaction Not Broadcast!'))
        return

    broadcasted_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            pubkeys=pubkeyhex_list,
            coin_symbol=coin_symbol,
    )
    verbose_print('Broadcast TX Details:')
    verbose_print(broadcasted_tx)

    tx_hash = broadcasted_tx['tx']['hash']
    tx_url = get_tx_url(
            tx_hash=tx_hash,
            coin_symbol=coin_symbol,
            )
    puts(colored.green('Transaction %s Broadcast' % tx_hash))
    puts(colored.blue(tx_url))

    # Display updated wallet balance info
    display_balance_info(wallet_obj=wallet_obj)


def generate_offline_tx(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to fetch unspents for signing.'))
        return

    # TODO: implement
    puts(colored.red('Feature Coming Soon'))


def sign_tx_offline(wallet_obj):

    if wallet_obj.private_key is None:
        puts(colored.red("bwallet was booted using a master PUBLIC key %s so it cannot sign transactions. Please load bwallet with your master PRIVATE key like this:"))
        priv_to_display = '%s123...' % first4mprv_from_mpub(
                mpub=wallet_obj.serialize_b58(private=False))
        print_bwallet_basic_priv_opening(priv_to_display=priv_to_display)
        puts(BWALLET_PRIVPIPE_EXPLANATION)
        print_bwallet_piped_priv_opening(priv_to_display=priv_to_display)
        return

    else:
        if USER_ONLINE:
            # double check in case we booted online and then disconnected
            if is_connected_to_blockcypher():
                puts(colored.red("You are connected to the internet while trying to sign a transaction offline. This feature is mainly used by developers who want to spend funds on their cold wallet without exposing their private keys. If you didn't mean to enter your master PRIVATE key on an internet connected machine, you may want to consider moving your funds to a cold wallet.\n"))

    # TODO: implement
    puts(colored.red('Feature Coming Soon'))


def broadcast_signed_tx(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to broadcast signed transaction.'))
        return

    # TODO: implement
    puts(colored.red('Feature Coming Soon'))


def sweep_funds_from_privkey(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to fetch unspents and broadcast signed transaction.'))
        return

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = str(coin_symbol_from_mkey(mpub))
    network = guess_network_from_mkey(mpub)

    puts('Enter a private key (in WIF format) to send from?')
    wif_obj = get_wif_obj(network=network, user_prompt=DEFAULT_PROMPT)

    pkey_addr = wif_obj.get_public_key().to_address(compressed=True)

    inputs = [{
            'address': pkey_addr,
            }, ]
    verbose_print('Inputs:\n%s' % inputs)

    dest_addr = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=1,
            )[0]['address']

    outputs = [{
            'address': dest_addr,
            'value': -1,  # sweep value
            }, ]
    verbose_print('Outputs:\n%s' % outputs)

    unsigned_tx = create_unsigned_tx(
        inputs=inputs,
        outputs=outputs,
        change_address=None,
        coin_symbol=coin_symbol,
        # will verify in the next step,
        # that way if there is an error here we can display that to user
        verify_tosigntx=False,
        include_tosigntx=True,
        )
    verbose_print('Unsigned TX:')
    verbose_print(unsigned_tx)

    if 'errors' in unsigned_tx:
        puts(colored.red('TX Error(s): Tx NOT Signed or Broadcast'))
        for error in unsigned_tx['errors']:
            puts(colored.red(error['error']))
        # Abandon
        return

    # Verify TX requested to sign is as expected
    tx_is_correct, err_msg = verify_unsigned_tx(
            unsigned_tx=unsigned_tx,
            inputs=inputs,
            outputs=outputs,
            sweep_funds=True,
            change_address=None,
            coin_symbol=coin_symbol,
            )
    if not tx_is_correct:
        puts(colored.red('TX Error: Tx NOT Signed or Broadcast'))
        puts(colored.red(err_msg))
        # Abandon
        return

    privkeyhex_list, pubkeyhex_list = [], []
    for _ in unsigned_tx['tx']['inputs']:
        privkeyhex_list.append(wif_obj.get_key())
        pubkeyhex_list.append(wif_obj.get_public_key().get_key(
            compressed=True))
    verbose_print('Private Key List: %s' % privkeyhex_list)
    verbose_print('Public Key List: %s' % pubkeyhex_list)

    # sign locally
    tx_signatures = make_tx_signatures(
            txs_to_sign=unsigned_tx['tosign'],
            privkey_list=privkeyhex_list,
            pubkey_list=pubkeyhex_list,
            )
    verbose_print('TX Signatures: %s' % tx_signatures)

    # TODO: add final confirmation before broadcast

    broadcasted_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            pubkeys=pubkeyhex_list,
            coin_symbol=coin_symbol,
    )
    verbose_print('Broadcasted TX')
    verbose_print(broadcasted_tx)

    tx_hash = broadcasted_tx['tx']['hash']
    puts(colored.green('TX Broadcast: %s' % tx_hash))
    tx_url = get_tx_url(
            tx_hash=tx_hash,
            coin_symbol=coin_symbol,
            )
    puts(colored.blue(tx_url))

    # Display updated wallet balance info
    display_balance_info(wallet_obj=wallet_obj)


def print_key_path_info(address, wif, path, coin_symbol, skip_nobalance=False):
    if path:
        path_display = path
    else:
        path_display = 'deeper traversal needed'

    if USER_ONLINE:
        addr_balance = get_total_balance(
                address=address,
                coin_symbol=coin_symbol,
                )
        if skip_nobalance and not addr_balance:
            # some addresses were used and subsequently emptied
            return

        with indent(2):
            puts(colored.green('%s (%s/%s) - %s satoshis (%s %s)' % (
                path_display,
                address,
                wif,
                format_with_k_separator(addr_balance),
                format_without_rounding(satoshis_to_btc(addr_balance)),
                COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
                )))
    else:
        with indent(2):
            puts(colored.green('%s (%s/%s)' % (
                    path_display,
                    address,
                    wif,
                    )))


def print_key_path_header():
    with indent(2):
        puts('path (address/wif)')


def print_address_path_info(address, path, coin_symbol, skip_nobalance=False):
        if path:
            path_display = path
        else:
            path_display = 'deeper traversal needed'

        if USER_ONLINE:
            addr_balance = get_total_balance(
                    address=address,
                    coin_symbol=coin_symbol,
                    )
            if skip_nobalance and not addr_balance:
                # some addresses were used and subsequently emptied
                return

            with indent(2):
                puts(colored.green('%s (%s) - %s satoshis (%s %s)' % (
                    path_display,
                    address,
                    format_with_k_separator(addr_balance),
                    format_without_rounding(satoshis_to_btc(addr_balance)),
                    COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
                    )))
        else:
            with indent(2):
                puts(colored.green('%s (%s)' % (
                    path_display,
                    address,
                    )))


def print_address_path_header():
    with indent(2):
        puts('path (address)')


def dump_all_keys(wallet_obj):

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)

    puts('How many private keys (on each chain) do you want to dump?')
    num_keys = get_int(
            user_prompt=DEFAULT_PROMPT,
            max_int=10**5,
            default_input='5',
            show_default=True,
            )

    puts('-' * 70 + '\n')
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    puts('External Chain - m/0/k:')
                    print_key_path_header()
                elif chain_int == 1:
                    puts('Internal Chain - m/1/k')
                    print_key_path_header()
            child_wallet = wallet_obj.get_child_for_path(path)
            print_key_path_info(
                    address=child_wallet.to_address(),
                    path=path,
                    wif=child_wallet.export_to_wif(),
                    coin_symbol=coin_symbol,
                    skip_nobalance=False,
                    )

    puts(colored.blue('You can compare this output to bip32.org'))


def dump_active_keys(wallet_obj):
    mpriv = wallet_obj.serialize_b58(private=True)
    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)
    used_addresses = list(get_used_addresses(wallet_obj=wallet_obj))

    # get active addresses
    hexkeypairs = find_hexkeypairs_from_bip32key_bc(
            pub_address_list=used_addresses,
            master_key=mpriv,
            network=guess_network_from_mkey(mpub),
            starting_pos=0,
            # TODO: get blockcypher to return paths for speed/quality increase
            depth=100,
            )

    for cnt, hexkeypair_dict in enumerate(hexkeypairs):
        if cnt == 0:
            print_key_path_header()
        print_key_path_info(
                address=hexkeypair_dict['pub_address'],
                wif=hexkeypair_dict['wif'],
                path=hexkeypair_dict['path'],
                coin_symbol=coin_symbol,
                skip_nobalance=True,
                )

    found_addresses = [x['pub_address'] for x in hexkeypairs]
    notfound_addrs = set(used_addresses) - set(found_addresses)

    for cnt, notfound_addr in enumerate(notfound_addrs):
        if cnt == 0:
            print_address_path_header()
        print_address_path_info(
                address=notfound_addr,
                path=None,
                coin_symbol=coin_symbol,
                skip_nobalance=True,
                )

    puts(colored.blue('You can compare this output to bip32.org'))


def dump_private_keys(wallet_obj):
    '''
    Offline-enabled mechanism to dump everything
    '''

    if USER_ONLINE:
        # Ask if they want active or all
        puts('Which private keys and addresses do you want?')
        with indent(2):
            puts(colored.cyan(' 1: All - regardless of whether they have funds to spend'))
            puts(colored.cyan(' 2: Active - those with funds to spend'))
        choice = choice_prompt(
                user_prompt=DEFAULT_PROMPT,
                acceptable_responses=[1, 2],
                default_input='1',
                show_default=True,
                )
        if choice == '1':
            return dump_all_keys(wallet_obj=wallet_obj)
        elif choice == '2':
            return dump_active_keys(wallet_obj=wallet_obj)

    return dump_all_keys(wallet_obj=wallet_obj)


def dump_all_addresses(wallet_obj):
    '''
    Offline-enabled mechanism to dump addresses
    '''

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)

    puts('How many addresses (on each chain) do you want to dump?')
    num_keys = get_int(
            max_int=10**5,
            user_prompt=DEFAULT_PROMPT,
            default_input='5',
            show_default=True,
            )

    puts('-' * 70 + '\n')
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    puts('External Chain Addresses - m/0/k:')
                    print_address_path_header()
                elif chain_int == 1:
                    puts('Internal Chain Addresses - m/1/k:')
                    print_address_path_header()
            child_wallet = wallet_obj.get_child_for_path(path)
            print_address_path_info(
                    address=child_wallet.to_address(),
                    path=path,
                    coin_symbol=coin_symbol,
                    skip_nobalance=False,
                    )

    puts(colored.blue('You can compare this output to bip32.org'))


def dump_active_addresses(wallet_obj):
    mpub = wallet_obj.serialize_b58(private=False)

    puts('Displaying Public Addresses Only')
    puts('For Private Keys, please open bwallet with your Master Private Key:\n')

    priv_to_display = '%s123...' % first4mprv_from_mpub(mpub=mpub)
    print_bwallet_basic_priv_opening(priv_to_display=priv_to_display)

    coin_symbol = coin_symbol_from_mkey(mpub)
    used_addresses = list(get_used_addresses(wallet_obj=wallet_obj))

    # get active addresses
    hexkeypairs = find_hexkeypairs_from_bip32key_bc(
            pub_address_list=used_addresses,
            master_key=mpub,
            network=guess_network_from_mkey(mpub),
            starting_pos=0,
            # TODO: get blockcypher to return paths for speed/quality increase
            depth=100,
            )

    for hexkeypair_dict in hexkeypairs:
        print_address_path_info(
                address=hexkeypair_dict['pub_address'],
                path=hexkeypair_dict['path'],
                coin_symbol=coin_symbol,
                skip_nobalance=True,
                )

    found_addresses = [x['pub_address'] for x in hexkeypairs]
    notfound_addrs = set(used_addresses) - set(found_addresses)

    for notfound_addr in notfound_addrs:
        print_address_path_info(
                address=notfound_addr,
                path=None,
                coin_symbol=coin_symbol,
                skip_nobalance=True,
                )

    puts(colored.blue('You can compare this output to bip32.org'))


def dump_addresses(wallet_obj):
    if USER_ONLINE:
        # Ask if they want active or all
        puts('Which addresses do you want?')
        with indent(2):
            puts(colored.cyan('1: All - regardless of whether they have funds to spend'))
            puts(colored.cyan('2: Active - those with funds to spend'))
        choice = choice_prompt(
                user_prompt=DEFAULT_PROMPT,
                acceptable_responses=[1, 2],
                default_input='1',
                show_default=True,
                )
        if choice == '1':
            return dump_all_addresses(wallet_obj=wallet_obj)
        elif choice == '2':
            return dump_active_addresses(wallet_obj=wallet_obj)

    return dump_all_addresses(wallet_obj=wallet_obj)


def send_chooser(wallet_obj):
    puts('What do you want to do?:')
    if not USER_ONLINE:
        puts("(since you are NOT connected to BlockCypher, many choices will not work)")
    with indent(2):
        puts(colored.cyan('1: Basic send (generate transaction, sign, & broadcast)'))
        puts(colored.cyan('2: Sweep funds into bwallet from a private key you hold'))
        puts(colored.cyan('3: Generate transaction for offline signing'))
        puts(colored.cyan('4: Sign transaction offline'))
        puts(colored.cyan('5: Broadcast transaction previously signed offline'))

    choice = choice_prompt(
            user_prompt=DEFAULT_PROMPT,
            acceptable_responses=range(0, 5+1),
            quit_ok=True,
            default_input='1',
            show_default=True,
            )
    verbose_print('Choice: %s' % choice)

    if choice in ('q', 'Q'):
        return
    elif choice == '1':
        return send_funds(wallet_obj=wallet_obj)
    elif choice == '2':
        return sweep_funds_from_privkey(wallet_obj=wallet_obj)
    elif choice == '3':
        return generate_offline_tx(wallet_obj=wallet_obj)
    elif choice == '4':
        return sign_tx_offline(wallet_obj=wallet_obj)
    elif choice == '5':
        return broadcast_signed_tx(wallet_obj=wallet_obj)


def wallet_home(wallet_obj):
    '''
    Loaded on bootup (and loops until quitting)
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    if wallet_obj.private_key is None:
        print_pubwallet_notice(mpub=mpub)
    else:
        puts("You've opened your wallet in PRIVATE key mode, so you CAN sign transactions.")
        puts("If you like, you can always open your wallet in PUBLIC key mode like this:\n")
        print_bwallet_basic_pub_opening(mpub=mpub)

    coin_symbol = coin_symbol_from_mkey(mpub)
    if USER_ONLINE:
        wallet_name = get_blockcypher_walletname_from_mpub(
                mpub=mpub,
                subchain_indices=[0, 1],
                )

        # Instruct blockcypher to track the wallet by pubkey
        create_hd_wallet(
                wallet_name=wallet_name,
                xpubkey=mpub,
                api_key=BLOCKCYPHER_API_KEY,
                coin_symbol=coin_symbol,
                subchain_indices=[0, 1],  # for internal and change addresses
                )

        # Display balance info
        display_balance_info(wallet_obj=wallet_obj)

    # Go to home screen
    while True:
        puts('-' * 70 + '\n')

        if coin_symbol in ('bcy', 'btc-testnet'):
            currency_abbrev = COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev']
            if coin_symbol == 'bcy':
                faucet_url = 'https://accounts.blockcypher.com/blockcypher-faucet'
            elif coin_symbol == 'btc-testnet':
                faucet_url = 'https://accounts.blockcypher.com/testnet-faucet'
            puts(colored.blue('Get free %s faucet coins at %s\n' % (
                currency_abbrev,
                faucet_url,
                )))

        puts('What do you want to do?:')
        if not USER_ONLINE:
            puts("(since you are NOT connected to BlockCypher, many choices are disabled)")
        with indent(2):
            puts(colored.cyan('1: Show new receiving addresses'))
            puts(colored.cyan('2: Show balance and transactions'))
            puts(colored.cyan('3: Send funds (more options here)'))

        if wallet_obj.private_key:
            with indent(2):
                puts(colored.cyan('0: Dump private keys and addresses (advanced users only)'))
        else:
            with indent(2):
                puts(colored.cyan('0: Dump addresses (advanced users only)'))

        choice = choice_prompt(
                user_prompt=DEFAULT_PROMPT,
                acceptable_responses=range(0, 3+1),
                quit_ok=True,
                )
        verbose_print('Choice: %s' % choice)

        if choice in ('q', 'Q'):
            puts(colored.green('Thanks for using bwallet!'))
            break
        elif choice == '1':
            display_new_receiving_addresses(wallet_obj=wallet_obj)
        elif choice == '2':
            display_recent_txs(wallet_obj=wallet_obj)
        elif choice == '3':
            send_chooser(wallet_obj=wallet_obj)
        elif choice == '0':
            if wallet_obj.private_key:
                dump_private_keys(wallet_obj=wallet_obj)
            else:
                dump_addresses(wallet_obj)


def cli():

    parser = argparse.ArgumentParser(
        description='''
    Simple BIP32 HD cryptocurrecy command line wallet supporting Bitcoin (and Testnet), Litecoin, Dogecoin, and BlockCypher testnet.

    Keys are generated from the seed and transactions are signed locally for trustless use.
    The seed is not stored locally, the app is booted with the user supplying the master key.
    Blockchain heavy lifting powered by BlockCypher.
    ''')
    parser.add_argument('-w', '--wallet',
            dest='wallet',
            default='',
            help='Master private or public key (starts with xprv and xpub for BTC). Can also be UNIX piped in (-w/--w not needed).',
            )
    parser.add_argument("-v", "--verbose",
            dest='verbose',
            default=False,
            action='store_true',
            help="Show detailed logging info",
            )
    parser.add_argument('-b', '--bc-api-key',
            dest='bc_api_key',
            # For all bwallet users:
            default='9c339f92713518492a4504c273d1d9f9',
            help='BlockCypher API Key to use. If not supplied the default will be used.',
            )
    parser.add_argument('--version',
            dest='version',
            default=False,
            action='store_true',
            help="Show version and quit",
            )
    args = parser.parse_args()

    if args.verbose:
        global VERBOSE_MODE
        VERBOSE_MODE = True
    verbose_print('args: %s' % args)

    if args.version:
        import pkg_resources
        puts(colored.green(str(pkg_resources.get_distribution("bwallet"))))
        sys.exit()

    if sys.stdin.isatty():
        wallet = args.wallet
        verbose_print('Wallet imported from args')
    else:
        wallet = sys.stdin.readline().strip()
        sys.stdin = open('/dev/tty')
        verbose_print('Wallet imported from pipe')
    verbose_print('wallet %s' % wallet)

    if args.bc_api_key:
        global BLOCKCYPHER_API_KEY
        BLOCKCYPHER_API_KEY = args.bc_api_key
        verbose_print('API Key: %s' % BLOCKCYPHER_API_KEY)
        # Crude check
        if set(BLOCKCYPHER_API_KEY) - set('0123456789abcdef'):
            puts(colored.red('Invalid API Key: %s' % BLOCKCYPHER_API_KEY))
            sys.exit()

    # Check if blockcypher is up (basically if the user's machine is online)
    global USER_ONLINE
    if is_connected_to_blockcypher():
        USER_ONLINE = True

    puts(colored.green("\nWelcome to bwallet!\n"))

    if wallet:
        network = guess_network_from_mkey(wallet)
        if network:
            # check if valid mkey
            try:
                wallet_obj = Wallet.deserialize(wallet, network=network)
                mpub = wallet_obj.serialize_b58(private=False)
                if wallet_obj.private_key is None:
                    # input was mpub
                    if mpub != wallet:
                        # safety check
                        puts(colored.red("Invalid entry: %s" % wallet))
            except IndexError:
                puts(colored.red("Invalid entry: %s" % wallet))

            # Run the program:
            return wallet_home(wallet_obj)

        else:
            puts(colored.red("Invalid wallet entry: %s" % wallet))

    else:
        puts("You've opened your wallet without specifying a master public or master private key, which you can do like this:\n")
        print_bwallet_basic_priv_opening(priv_to_display='xpriv123...')
        puts("Let's generate a new master private key (locally) for you to use.\n")
        puts('Which currency do you want to create a wallet for?')
        coin_symbol = coin_symbol_chooser(user_prompt=DEFAULT_PROMPT)
        verbose_print(coin_symbol)
        network = COIN_SYMBOL_TO_BMERCHANT_NETWORK[coin_symbol]

        puts("\nLet's add some extra entropy in case you're on a fresh boot of a virtual machine, or your random number generator has been compromised by an unnamed three letter agency. Please bang on the keyboard for as long as you like and then hit enter. There's no reason to record this value, it cannot be used to recover your keys.")
        extra_entropy = get_user_entropy(user_prompt='฿ (optional)')

        verbose_print(extra_entropy)
        # worst-case assumption (attacker knows keyspace and length)
        entropy_space = len(extra_entropy) ** len(set(extra_entropy))
        bits_entropy = len(bin(entropy_space)) - 2
        verbose_print('bits of extra_entropy: %s' % bits_entropy)

        user_wallet_obj = Wallet.new_random_wallet(network=network,
                user_entropy=extra_entropy)
        mpriv = user_wallet_obj.serialize_b58(private=True)
        mpub = user_wallet_obj.serialize_b58(private=False)

        # Dump info to screen and exit
        puts(colored.green('\nYour master PRIVATE key is: %s (guard this CAREFULLY as it can be used to steal your funds)' % mpriv))
        puts(colored.green('Your master PUBLIC key is: %s\n' % mpub))
        puts('bwallet will now quit. Open your new wallet anytime like this:\n')
        print_bwallet_basic_priv_opening(priv_to_display=mpriv)
        puts(BWALLET_PRIVPIPE_EXPLANATION)
        print_bwallet_piped_priv_opening(priv_to_display=mpriv)
        sys.exit()


def invoke_cli():
    try:
        cli()
    except KeyboardInterrupt:
        puts(colored.red('\nAborted'))
        sys.exit()


if __name__ == '__main__':
    '''
    For (rare) invocation like this:
    python bwallet.py
    '''
    invoke_cli()
