# -*- coding: utf-8 -*-

import sys
import argparse

# just for printing
from clint.textui import puts, colored, indent

from bitmerchant.wallet import Wallet

from blockcypher import (create_hd_wallet, get_wallet_transactions,
        get_wallet_addresses, derive_hd_address,
        create_unsigned_tx, verify_unsigned_tx, get_input_addresses,
        make_tx_signatures, broadcast_signed_transaction,
        get_blockchain_overview, get_total_balance)
from blockcypher.utils import (get_blockcypher_walletname_from_mpub,
        coin_symbol_from_mkey, format_crypto_units, from_satoshis, to_satoshis)
from blockcypher.constants import COIN_SYMBOL_MAPPINGS

from .bc_utils import (guess_network_from_mkey, verify_and_fill_address_paths_from_bip32key,
        find_hexkeypairs_from_bip32key_bc, get_tx_url, hexkeypair_list_to_dict,
        COIN_SYMBOL_TO_BMERCHANT_NETWORK)

from .cl_utils import (debug_print, choice_prompt,
        get_crypto_address, get_wif_obj,
        get_crypto_qty, get_int,
        confirm, get_user_entropy, coin_symbol_chooser, txn_preference_chooser,
        first4mprv_from_mpub, print_pubwallet_notice,
        print_bcwallet_basic_priv_opening, print_bcwallet_piped_priv_opening,
        print_bcwallet_basic_pub_opening,
        UNIT_CHOICES, BCWALLET_PRIVPIPE_EXPLANATION, DEFAULT_PROMPT)

import traceback

from tzlocal import get_localzone


# Globals that can be overwritten at startup
VERBOSE_MODE = False
USER_ONLINE = False
BLOCKCYPHER_API_KEY = ''
UNIT_CHOICE = ''


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

    wallet_details = get_wallet_transactions(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol,
            )
    verbose_print(wallet_details)

    puts('-' * 70 + '\n')
    balance_str = 'Balance: %s' % (
            format_crypto_units(
                input_quantity=wallet_details['final_balance'],
                input_type=UNIT_CHOICE,
                output_type=UNIT_CHOICE,
                coin_symbol=coin_symbol,
                print_cs=True,
            ))
    puts(colored.green(balance_str))
    if wallet_details['unconfirmed_balance']:
        balance_str += ' (%s%s of this is unconfirmed)' % (
                '+' if wallet_details['unconfirmed_balance'] else '',  # hack
                format_crypto_units(
                    input_quantity=wallet_details['unconfirmed_balance'],
                    input_type=UNIT_CHOICE,
                    output_type=UNIT_CHOICE,
                    print_cs=True,
                    coin_symbol=coin_symbol,
                ),
                )

    tx_string = 'Transactions: %s' % wallet_details['final_n_tx']
    if wallet_details['unconfirmed_n_tx']:
        tx_string += ' (%s unconfirmed)' % wallet_details['unconfirmed_n_tx']
    puts(colored.green(tx_string))

    return wallet_details['final_balance']


def get_addresses_on_both_chains(wallet_obj, used=None, zero_balance=None):
    '''
    Get addresses across both subchains based on the filter criteria passed in

    Returns a list of dicts of the following form:
        [
            {'address': '1abc123...', 'path': 'm/0/9', 'pubkeyhex': '0123456...'},
            ...,
        ]

    Dicts may also contain WIF and privkeyhex if wallet_obj has private key
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )

    wallet_addresses = get_wallet_addresses(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            is_hd_wallet=True,
            used=used,
            zero_balance=zero_balance,
            coin_symbol=coin_symbol_from_mkey(mpub),
            )
    verbose_print('wallet_addresses:')
    verbose_print(wallet_addresses)

    if wallet_obj.private_key:
        master_key = wallet_obj.serialize_b58(private=True)
    else:
        master_key = mpub

    chains_address_paths_cleaned = []
    for chain in wallet_addresses['chains']:
        chain_address_paths = verify_and_fill_address_paths_from_bip32key(
                address_paths=chain['chain_addresses'],
                master_key=master_key,
                network=guess_network_from_mkey(mpub),
                )
        chain_address_paths_cleaned = {
                'index': chain['index'],
                'chain_addresses': chain_address_paths,
                }
        chains_address_paths_cleaned.append(chain_address_paths_cleaned)

    return chains_address_paths_cleaned


def register_unused_addresses(wallet_obj, subchain_index, num_addrs=1):
    '''
    Hit /derive to register new unused_addresses on a subchain_index and verify them client-side

    Returns a list of dicts of the following form:
        [
            {'address': '1abc123...', 'path': 'm/0/9', 'public': '0123456...'},
            ...,
        ]
    '''

    verbose_print('register_unused_addresses called on subchain %s for %s addrs' % (
        subchain_index,
        num_addrs,
        ))

    assert type(subchain_index) is int, subchain_index
    assert type(num_addrs) is int, num_addrs
    assert num_addrs > 0

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)
    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )
    network = guess_network_from_mkey(mpub)

    # register new address(es)
    derivation_response = derive_hd_address(
            api_key=BLOCKCYPHER_API_KEY,
            wallet_name=wallet_name,
            num_addresses=num_addrs,
            subchain_index=subchain_index,
            coin_symbol=coin_symbol,
            )

    verbose_print('derivation_response:')
    verbose_print(derivation_response)

    address_paths = derivation_response['chains'][0]['chain_addresses']

    # verify new addresses client-side
    full_address_paths = verify_and_fill_address_paths_from_bip32key(
            address_paths=address_paths,
            master_key=mpub,
            network=network,
            )

    return full_address_paths


def get_unused_receiving_addresses(wallet_obj, num_addrs=1):

    return register_unused_addresses(
            wallet_obj=wallet_obj,
            subchain_index=0,  # external chain
            num_addrs=num_addrs,
            )


def get_unused_change_addresses(wallet_obj, num_addrs=1):
    return register_unused_addresses(
            wallet_obj=wallet_obj,
            subchain_index=1,  # internal chain
            num_addrs=num_addrs,
            )


def display_new_receiving_addresses(wallet_obj):

    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to see which addresses have been used.'))
        puts(colored.red('You may dump all your addresses offline by selecting option 0.'))
        return

    mpub = wallet_obj.serialize_b58(private=False)

    puts('How many receiving addreses keys do you want to see (max 5)?')
    num_addrs = get_int(
            user_prompt=DEFAULT_PROMPT,
            min_int=1,
            max_int=5,
            default_input='1',
            show_default=True,
            quit_ok=True,
            )

    if num_addrs in ('q', 'Q'):
        return

    verbose_print('num_addrs:\n%s' % num_addrs)

    unused_receiving_addresses = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs=num_addrs,
            )

    puts('-' * 70 + '\n')
    if num_addrs > 1:
        addr_str = 'Addresses'
    else:
        addr_str = 'Address'

    puts('Unused %s Receiving %s - (for others to send you funds):' % (
        COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev'],
        addr_str,
        ))

    for unused_receiving_address in unused_receiving_addresses:
        with indent(2):
            puts(colored.green('%s (path is %s)' % (
                unused_receiving_address['pub_address'],
                unused_receiving_address['path'],
                )))


def display_recent_txs(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('BlockCypher connection needed to find transactions related to your addresses.'))
        puts(colored.red('You may dump all your addresses while offline by selecting option 0.'))
        return

    local_tz = get_localzone()

    # Show overall balance info
    display_balance_info(wallet_obj=wallet_obj)

    mpub = wallet_obj.serialize_b58(private=False)
    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indices=[0, 1],
            )

    wallet_details = get_wallet_transactions(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol_from_mkey(mpub),
            )
    verbose_print(wallet_details)

    # TODO: pagination for lots of transactions

    txs = wallet_details.get('unconfirmed_txrefs', []) + wallet_details.get('txrefs', [])

    if not txs:
        puts('No Transactions')

    for tx in txs:
        # Logic copied from block explorer
        # templates/address_overview.html
        if tx.get('received'):
            tx_time = tx.get('received')
        else:
            tx_time = tx.get('confirmed')

        satoshis = tx.get('value', 0)

        # HACK!
        if tx.get('tx_input_n') >= 0:
            action_str = 'sent'
            sign_str = '-'
        else:
            action_str = 'received'
            sign_str = '+'

        puts(colored.green('%s: %s%s %s in TX hash %s' % (
            tx_time.astimezone(local_tz).strftime("%Y-%m-%d %H:%M %Z"),
            sign_str,
            format_crypto_units(
                input_quantity=satoshis,
                input_type=UNIT_CHOICE,
                output_type=UNIT_CHOICE,
                coin_symbol=coin_symbol_from_mkey(mpub),
                print_cs=True,
                ),
            action_str,
            tx.get('tx_hash'),
            )))

    puts(colored.blue('\nMore info: %s\n' % get_public_wallet_url(mpub)))


def send_funds(wallet_obj, destination_address=None, dest_satoshis=None, tx_preference=None):
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
    wallet_details = get_wallet_transactions(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol,
            )
    verbose_print(wallet_details)

    if wallet_details['final_balance'] == 0:
        puts(colored.red("0 balance. You can't send funds if you don't have them available!"))
        return

    mpriv = wallet_obj.serialize_b58(private=True)

    if not destination_address:
        display_shortname = COIN_SYMBOL_MAPPINGS[coin_symbol]['display_shortname']
        puts('What %s address do you want to send to?' % display_shortname)
        destination_address = get_crypto_address(coin_symbol=coin_symbol, quit_ok=True)
        if destination_address in ('q', 'Q'):
            puts(colored.red('Transaction Not Broadcast!'))
            return

    if not dest_satoshis:

        VALUE_PROMPT = 'Your current balance is %s. How much (in %s) do you want to send? Note that due to transaction fees your full balance may not be available to send.' % (
                format_crypto_units(
                    input_quantity=wallet_details['final_balance'],
                    input_type='satoshi',
                    output_type=UNIT_CHOICE,
                    coin_symbol=coin_symbol,
                    print_cs=True,
                    ),
                UNIT_CHOICE,
                )
        puts(VALUE_PROMPT)
        dest_crypto_qty = get_crypto_qty(
                max_num=from_satoshis(
                    input_satoshis=wallet_details['final_balance'],
                    output_type=UNIT_CHOICE,
                    ),
                input_type=UNIT_CHOICE,
                user_prompt=DEFAULT_PROMPT,
                quit_ok=True,
                )
        if dest_crypto_qty in ('q', 'Q'):
            puts(colored.red('Transaction Not Broadcast!'))
            return
        dest_satoshis = to_satoshis(
                input_quantity=dest_crypto_qty,
                input_type=UNIT_CHOICE,
                )

    inputs = [{
            'wallet_name': wallet_name,
            'wallet_token': BLOCKCYPHER_API_KEY,
            }, ]
    outputs = [{
            'value': dest_satoshis,
            'address': destination_address,
            }, ]

    if dest_satoshis == -1:
        sweep_funds = True
        change_address = None
    else:
        sweep_funds = False
        change_address = get_unused_change_addresses(
                wallet_obj=wallet_obj,
                num_addrs=1,
                )[0]['pub_address']

    if not tx_preference:
        tx_preference = txn_preference_chooser(user_prompt=DEFAULT_PROMPT)

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
        if any([x.get('error', '').startswith('Not enough funds after fees') for x in unsigned_tx['errors']]):
            puts("Sorry, after transaction fees there's not (quite) enough funds to send %s. Would you like to send the max you can instead?" % (
                format_crypto_units(
                    input_quantity=dest_satoshis,
                    input_type='satoshi',
                    output_type=UNIT_CHOICE,
                    coin_symbol=coin_symbol,
                    print_cs=True,
                )))
            if confirm(user_prompt=DEFAULT_PROMPT, default=False):
                return send_funds(
                        wallet_obj=wallet_obj,
                        destination_address=destination_address,
                        dest_satoshis=-1,  # sweep
                        tx_preference=tx_preference,
                        )
            else:
                puts(colored.red('Transaction Not Broadcast!'))
                return

        else:
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
            sweep_funds=sweep_funds,
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

    if len(hexkeypair_dict.keys()) != len(set(input_addresses)):
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

    if dest_satoshis == -1:
        # remember that sweep TXs cannot verify amounts client-side (only destination addresses)
        dest_satoshis_to_display = unsigned_tx['tx']['total'] - unsigned_tx['tx']['fees']
    else:
        dest_satoshis_to_display = dest_satoshis

    CONF_TEXT = "Send %s to %s with a fee of %s (%s%% of the amount you're sending)?" % (
            format_crypto_units(
                input_quantity=dest_satoshis_to_display,
                input_type='satoshi',
                output_type=UNIT_CHOICE,
                coin_symbol=coin_symbol,
                print_cs=True,
                ),
            destination_address,
            format_crypto_units(
                input_quantity=unsigned_tx['tx']['fees'],
                input_type='satoshi',
                output_type=UNIT_CHOICE,
                coin_symbol=coin_symbol,
                print_cs=True,
                ),
            round(100.0 * unsigned_tx['tx']['fees'] / dest_satoshis_to_display, 4),
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
        puts(colored.red("bcwallet was booted using a master PUBLIC key %s so it cannot sign transactions. Please load bcwallet with your master PRIVATE key like this:"))
        priv_to_display = '%s123...' % first4mprv_from_mpub(
                mpub=wallet_obj.serialize_b58(private=False))
        print_bcwallet_basic_priv_opening(priv_to_display=priv_to_display)
        puts(BCWALLET_PRIVPIPE_EXPLANATION)
        print_bcwallet_piped_priv_opening(priv_to_display=priv_to_display)
        return

    else:
        if USER_ONLINE:
            # double check in case we booted online and then disconnected
            if is_connected_to_blockcypher():
                puts(colored.red("Why are you trying to sign a transaction offline while connected to the internet? This feature is for developers to spend funds on their cold wallet without exposing their private keys to an internet connected machine. If you didn't mean to enter your master PRIVATE key on an internet connected machine, you may want to consider moving your funds to a cold wallet.\n"))

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

    puts('Enter a private key (in WIF format) to send from:')
    wif_obj = get_wif_obj(network=network, user_prompt=DEFAULT_PROMPT)

    pkey_addr = wif_obj.get_public_key().to_address(compressed=True)

    inputs = [{
            'address': pkey_addr,
            }, ]
    verbose_print('Inputs:\n%s' % inputs)

    dest_addr = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs=1,
            )[0]['pub_address']

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


def print_external_chain():
    puts('\nExternal Chain - m/0/k:')


def print_internal_chain():
    puts('\nInternal Chain - m/1/k')


def print_key_path_header():
    puts('path (address/wif)')


def print_address_path_header():
    puts('path (address)')


def print_path_info(address, path, coin_symbol, wif=None):

    assert path, path
    assert coin_symbol, coin_symbol
    assert address, address

    if wif:
        address_formatted = '%s/%s' % (address, wif)
    else:
        address_formatted = address

    if USER_ONLINE:
        addr_balance = get_total_balance(
                address=address,
                coin_symbol=coin_symbol,
                )

        with indent(2):
            puts(colored.green('%s (%s) - %s' % (
                path,
                address_formatted,
                format_crypto_units(
                    input_quantity=addr_balance,
                    input_type='satoshi',
                    output_type=UNIT_CHOICE,
                    coin_symbol=coin_symbol,
                    print_cs=True,
                    ),
                )))
    else:
        with indent(2):
            puts(colored.green('%s (%s)' % (
                path,
                address_formatted,
                )))


def dump_all_keys_or_addrs(wallet_obj):
    '''
    Offline-enabled mechanism to dump addresses
    '''

    mpub = wallet_obj.serialize_b58(private=False)

    if wallet_obj.private_key:
        puts('How many private keys (on each chain) do you want to dump?')
    else:
        puts('Displaying Public Addresses Only')
        puts('For Private Keys, please open bcwallet with your Master Private Key:\n')
        priv_to_display = '%s123...' % first4mprv_from_mpub(mpub=mpub)
        print_bcwallet_basic_priv_opening(priv_to_display=priv_to_display)
        puts('How many addresses (on each chain) do you want to dump?')

    num_keys = get_int(
            user_prompt=DEFAULT_PROMPT,
            max_int=10**5,
            default_input='5',
            show_default=True,
            )

    puts('-' * 70)
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    print_external_chain()
                    print_key_path_header()
                elif chain_int == 1:
                    print_internal_chain()
                    print_key_path_header()
            child_wallet = wallet_obj.get_child_for_path(path)
            if wallet_obj.private_key:
                wif_to_use = child_wallet.export_to_wif()
            else:
                wif_to_use = None
            print_path_info(
                    address=child_wallet.to_address(),
                    path=path,
                    wif=wif_to_use,
                    coin_symbol=coin_symbol_from_mkey(mpub),
                    )

    puts(colored.blue('\nYou can compare this output to bip32.org'))

    puts("\nNOTE: There are over a billion keys (and corresponding addresses) that can easily be derived from your master key, but that doesn't mean BlockCypher will automatically detect a transaction sent to any one of them. By default, BlockCypher will look 10 addresses ahead of the latest transaction or registered address on each subchain. For example, if the transaction that has traversed furthest on the internal chain is at m/0/5, then BlockCypher will automatically detect any transactions sent to m/0/0-m/0/15. For normal bcwallet users you never have to think about this, but if you're in this section manually traversing keys then it's important to consider. This feature should primarily be considered a last resource to migrate away from bcwallet if blockcypher is down.")


def dump_selected_keys_or_addrs(wallet_obj, used=None, zero_balance=None):
    '''
    Works for both public key only or private key access
    '''
    if wallet_obj.private_key:
        content_str = 'private keys'
    else:
        content_str = 'addresses'

    if not USER_ONLINE:
        puts(colored.red('\nInternet connection required, would you like to dump *all* %s instead?' % (
            content_str,
            content_str,
            )))
        if confirm(user_prompt=DEFAULT_PROMPT, default=True):
            dump_all_keys_or_addrs(wallet_obj=wallet_obj)
        else:
            return

    mpub = wallet_obj.serialize_b58(private=False)

    if wallet_obj.private_key is None:
        puts('Displaying Public Addresses Only')
        puts('For Private Keys, please open bcwallet with your Master Private Key:\n')
        priv_to_display = '%s123...' % first4mprv_from_mpub(mpub=mpub)
        print_bcwallet_basic_priv_opening(priv_to_display=priv_to_display)

    chain_address_objs = get_addresses_on_both_chains(
            wallet_obj=wallet_obj,
            used=used,
            zero_balance=zero_balance,
            )

    addr_cnt = 0
    for chain_address_obj in chain_address_objs:
        if chain_address_obj['index'] == 0:
            print_external_chain()
        elif chain_address_obj['index'] == 1:
            print_internal_chain()
        print_key_path_header()
        for address_obj in chain_address_obj['chain_addresses']:

            print_path_info(
                    address=address_obj['pub_address'],
                    wif=address_obj['wif'],
                    path=address_obj['path'],
                    coin_symbol=coin_symbol_from_mkey(mpub),
                    )

            addr_cnt += 1

    if addr_cnt:
        puts(colored.blue('\nYou can compare this output to bip32.org'))
    else:
        puts('No matching %s in this subset. Would you like to dump *all* %s instead?' % (
            content_str,
            content_str,
            ))
        if confirm(user_prompt=DEFAULT_PROMPT, default=True):
            dump_all_keys_or_addrs(wallet_obj=wallet_obj)


def dump_private_keys_or_addrs_chooser(wallet_obj):
    '''
    Offline-enabled mechanism to dump everything
    '''

    if wallet_obj.private_key:
        puts('Which private keys and addresses do you want?')
    else:
        puts('Which addresses do you want?')
    with indent(2):
        puts(colored.cyan(' 1: All (works offline) - regardless of whether they have funds to spend'))
        puts(colored.cyan(' 2: Active - have funds to spend'))
        puts(colored.cyan(' 3: Spent - no funds to spend (because they have been spent)'))
        puts(colored.cyan(' 4: Unused - no funds to spend (because the address has never been used)'))
    choice = choice_prompt(
            user_prompt=DEFAULT_PROMPT,
            acceptable_responses=[1, 2, 3, 4],
            default_input='1',
            show_default=True,
            quit_ok=True,
            )

    if choice in ('q', 'Q'):
        return

    if wallet_obj.private_key:
        puts("\nNOTE: Do not reveal your private keys to anyone! One quirk of HD wallets is that if an attacker learns any of your non-hardened child private keys as well as your master public key then the attacker can derive all of your private keys and steal all of your funds.\n")

    if choice == '1':
        return dump_all_keys_or_addrs(wallet_obj=wallet_obj)
    elif choice == '2':
        return dump_selected_keys_or_addrs(wallet_obj=wallet_obj, zero_balance=False, used=True)
    elif choice == '3':
        return dump_selected_keys_or_addrs(wallet_obj=wallet_obj, zero_balance=True, used=True)
    elif choice == '4':
        return dump_selected_keys_or_addrs(wallet_obj=wallet_obj, zero_balance=None, used=False)


def offline_tx_chooser(wallet_obj):
    puts('What do you want to do?:')
    puts(colored.cyan('1: Generate transaction for offline signing'))
    puts(colored.cyan('2: Sign transaction offline'))
    puts(colored.cyan('3: Broadcast transaction previously signed offline'))
    choice = choice_prompt(
            user_prompt=DEFAULT_PROMPT,
            acceptable_responses=range(0, 3+1),
            quit_ok=True,
            default_input='1',
            show_default=True,
            )
    verbose_print('Choice: %s' % choice)

    if choice in ('q', 'Q'):
        return
    elif choice == '1':
        return generate_offline_tx(wallet_obj=wallet_obj)
    elif choice == '2':
        return sign_tx_offline(wallet_obj=wallet_obj)
    elif choice == '3':
        return broadcast_signed_tx(wallet_obj=wallet_obj)


def send_chooser(wallet_obj):
    puts('What do you want to do?:')
    if not USER_ONLINE:
        puts("(since you are NOT connected to BlockCypher, many choices are disabled)")
    with indent(2):
        puts(colored.cyan('1: Basic send (generate transaction, sign, & broadcast)'))
        puts(colored.cyan('2: Sweep funds into bcwallet from a private key you hold'))
        puts(colored.cyan('3: Offline transaction signing (more here)'))

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
        offline_tx_chooser(wallet_obj=wallet_obj)


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
        print_bcwallet_basic_pub_opening(mpub=mpub)

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
            puts(colored.cyan('1: Show balance and transactions'))
            puts(colored.cyan('2: Show new receiving addresses'))
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
                default_input='1',
                )
        verbose_print('Choice: %s' % choice)

        if choice in ('q', 'Q'):
            puts(colored.green('Thanks for using bcwallet!'))
            break
        elif choice == '1':
            display_recent_txs(wallet_obj=wallet_obj)
        elif choice == '2':
            display_new_receiving_addresses(wallet_obj=wallet_obj)
        elif choice == '3':
            send_chooser(wallet_obj=wallet_obj)
        elif choice == '0':
            dump_private_keys_or_addrs_chooser(wallet_obj=wallet_obj)


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
            # For all bcwallet users:
            default='9c339f92713518492a4504c273d1d9f9',
            help='BlockCypher API Key to use. If not supplied the default will be used.',
            )
    parser.add_argument('-u', '--units',
            dest='units',
            default='bit',
            choices=UNIT_CHOICES,
            help='Units to represent the currency in user display.',
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

    global UNIT_CHOICE
    UNIT_CHOICE = args.units

    if args.version:
        import pkg_resources
        puts(colored.green(str(pkg_resources.get_distribution("bcwallet"))))
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

    puts(colored.green("\nWelcome to bcwallet!\n"))

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
        print_bcwallet_basic_priv_opening(priv_to_display='xpriv123...')

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

        puts(colored.green('\nYour master PRIVATE key is: %s (guard this CAREFULLY as it can be used to steal your funds)' % mpriv))
        puts(colored.green('Your master PUBLIC key is: %s\n' % mpub))
        puts('bcwallet will now quit. Open your new wallet anytime like this:\n')
        print_bcwallet_basic_priv_opening(priv_to_display=mpriv)
        puts(BCWALLET_PRIVPIPE_EXPLANATION)
        print_bcwallet_piped_priv_opening(priv_to_display=mpriv)
        sys.exit()


def invoke_cli():
    if sys.version_info[0] != 2 or sys.version_info[1] != 7:
        puts(colored.red('Sorry, this app must be run with python 2.7 :('))
        puts(colored.red('Your version: %s' % sys.version))
    try:
        cli()
    except KeyboardInterrupt:
        puts(colored.red('\nAborted'))
        sys.exit()
    except Exception as e:
        puts(colored.red('\nBad Robot! Quitting on Unexpected Error:\n%s' % e))
        puts('\nHere are the details to share with the developer for a bug report')
        puts(colored.yellow(traceback.format_exc()))
        sys.exit()

if __name__ == '__main__':
    '''
    For (rare) invocation like this:
    python bcwallet.py
    '''
    invoke_cli()
