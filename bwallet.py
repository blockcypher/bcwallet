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

from bc_utils import (guess_network_from_mkey,
        find_hexkeypairs_from_bip32key_bc, get_tx_url, hexkeypair_list_to_dict,
        COIN_SYMBOL_TO_BMERCHANT_NETWORK)

from cl_utils import (print_without_rounding, debug_print, choice_prompt,
        get_crypto_address, get_wif_obj, get_int, confirm, get_user_entropy,
        coin_symbol_chooser, txn_preference_chooser, DEFAULT_PROMPT)


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

    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_API_KEY,
            coin_symbol=coin_symbol_from_mkey(mpub),
            )
    verbose_print(wallet_details)

    puts('-' * 50)
    puts('Total Received: %s' % wallet_details['total_received'])
    puts('Total Sent: %s' % wallet_details['total_sent'])
    puts('Balance: %s' % wallet_details['final_balance'])
    if wallet_details['unconfirmed_n_tx']:
        puts('Transactions: %s (%s Unconfirmed)' % (
            wallet_details['final_n_tx'],
            wallet_details['unconfirmed_n_tx'],
            ))
    else:
        puts('Transactions: %s' % wallet_details['final_n_tx'])

    puts(colored.blue('For details, see: %s' % get_public_wallet_url(mpub)))

    return


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
        puts(colored.red('Blockcypher connection needed to see which addresses have been used.'))
        puts(colored.red('You may dump all your addresses while offline by selecting option 0.'))
        return

    mpub = wallet_obj.serialize_b58(private=False)

    unused_receiving_addresses = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=5,
            )

    puts('-' * 75)
    puts('Next 5 Unused %s Receiving Addresses (for people to send you funds):' %
            COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev']
            )

    for unused_receiving_address in unused_receiving_addresses:
        with indent(2):
            puts('%s (path is %s)' % (
                unused_receiving_address['address'],
                unused_receiving_address['path'],
                ))


def display_recent_txs(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('Blockcypher connection needed to find transactions related to your addresses.'))
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
        puts('Transaction %s: %s satoshis (%s %s) %s' % (
            tx.get('tx_hash'),
            tx.get('value'),
            print_without_rounding(satoshis_to_btc(tx.get('value', 0))),
            COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev'],
            'sent' if tx.get('tx_input_n') >= 0 else 'received',  # HACK!
            ))


def send_funds(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('Blockcypher connection needed to fetch unspents and broadcast signed transaction.'))
        puts(colored.red('You may dump all your addresses and private keys while offline by selecting option 0.'))
        return

    mpub = wallet_obj.serialize_b58(private=False)
    mpriv = wallet_obj.serialize_b58(private=True)

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

    display_shortname = COIN_SYMBOL_MAPPINGS[coin_symbol]['display_shortname']
    puts('What %s address do you want to send to?' % display_shortname)
    destination_address = get_crypto_address(coin_symbol=coin_symbol)

    VALUE_PROMPT = 'Your current balance is %s (in satoshis). How much do you want to send? Note that due to transaction fes your full balance may not be available to send.' % (
            wallet_details['balance'])
    puts(VALUE_PROMPT)
    dest_satoshis = get_int(
            max_int=wallet_details['balance'],
            user_prompt=DEFAULT_PROMPT,
            )

    # TODO: add ability to set tx confirmation preference

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

    tx_preference = txn_preference_chooser(default_input='1')

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
        )

    verbose_print('Unsigned TX:')
    verbose_print(unsigned_tx)

    if 'errors' in unsigned_tx:
        puts(colored.red('TX Error(s): Tx NOT Signed or Broadcast'))
        for error in unsigned_tx['errors']:
            puts(colored.red(error['error']))
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

    CONF_TEXT = 'Send %s satoshis (%s %s) to %s' % (
            dest_satoshis,
            print_without_rounding(satoshis_to_btc(dest_satoshis)),
            COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
            destination_address,
            )

    puts(CONF_TEXT)
    if not confirm(user_prompt='฿:', default=True):
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
    # TODO: implement
    puts('Feature Coming Soon')


def broadcast_signed_tx(wallet_obj):
    # TODO: implement
    puts('Feature Coming Soon')


def sweep_funds_from_privkey(wallet_obj):
    if not USER_ONLINE:
        puts(colored.red('Blockcypher connection needed to fetch unspents and broadcast signed transaction.'))
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
        )
    verbose_print('Unsigned TX:')
    verbose_print(unsigned_tx)

    if 'errors' in unsigned_tx:
        puts(colored.red('TX Error(s): Tx NOT Signed or Broadcast'))
        for error in unsigned_tx['errors']:
            puts(colored.red(error['error']))
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
    puts(tx_hash)
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
            puts('%s (%s/%s) - %s satoshis (%s %s)' % (
                path_display,
                address,
                wif,
                addr_balance,
                print_without_rounding(satoshis_to_btc(addr_balance)),
                COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
                ))
    else:
        with indent(2):
            puts('%s (%s/%s)' % (
                    path_display,
                    address,
                    wif,
                    ))


def dump_all_keys(wallet_obj):

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)

    puts('How many private keys (on each chain) do you want to dump?')
    num_keys = get_int(
            user_prompt=DEFAULT_PROMPT,
            max_int=10**5,
            default_input=5,
            )

    puts('-'*50)
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    puts('External Chain:')
                elif chain_int == 1:
                    puts('Internal Chain:')
            child_wallet = wallet_obj.get_child_for_path(path)
            print_key_path_info(
                    address=child_wallet.to_address(),
                    path=path,
                    wif=child_wallet.export_to_wif(),
                    coin_symbol=coin_symbol,
                    skip_nobalance=False,
                    )


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

    for hexkeypair_dict in hexkeypairs:
        print_key_path_info(
                address=hexkeypair_dict['pub_address'],
                wif=hexkeypair_dict['wif'],
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


def dump_private_keys(wallet_obj):
    '''
    Offline-enabled mechanism to dump everything
    '''

    if USER_ONLINE:
        # Ask if they want active or all
        puts('Which private keys do you want?')
        with indent(2):
            puts(colored.cyan(' 1: All private keys (regardless of whether they have funds to spend)'))
            puts(colored.cyan(' 2: Active private keys (those with funds to spend)'))
        choice = choice_prompt(
                user_prompt=DEFAULT_PROMPT,
                acceptable_responses=[1, 2],
                default_input=1,
                show_default=False,
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
            default_input=5,
            )

    puts('-'*50)
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    puts('External Chain Addresses:')
                elif chain_int == 1:
                    puts('Internal Chain Addresses:')
                with indent(2):
                    puts('address (path)')
            child_wallet = wallet_obj.get_child_for_path(path)
            print_address_path_info(
                    address=child_wallet.to_address(),
                    path=path,
                    coin_symbol=coin_symbol,
                    skip_nobalance=False,
                    )


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
                puts('%s (%s) - %s satoshis (%s %s)' % (
                    address,
                    path_display,
                    addr_balance,
                    print_without_rounding(satoshis_to_btc(addr_balance)),
                    COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
                    ))
        else:
            with indent(2):
                puts('%s (%s)' % (
                    address,
                    path_display,
                    ))


def dump_active_addresses(wallet_obj):
    puts('Displaying Public Addresses Only')
    puts('For Private Keys, please open bwallet with your Master Private Key:')
    puts('')
    with indent(2):
        puts(colored.magenta('$ bwallet --wallet=xpriv123...'))

    mpub = wallet_obj.serialize_b58(private=False)
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


def dump_addresses(wallet_obj):
    if USER_ONLINE:
        # Ask if they want active or all
        puts('Which addresses do you want?')
        with indent(2):
            puts(colored.cyan('1: All addresses (regardless of whether they have funds to spend)'))
            puts(colored.cyan('2: Active addresses (those with funds to spend)'))
        choice = choice_prompt(
                user_prompt=DEFAULT_PROMPT,
                acceptable_responses=[1, 2],
                default_input=1,
                show_default=False,
                )
        if choice == '1':
            return dump_all_addresses(wallet_obj=wallet_obj)
        elif choice == '2':
            return dump_active_addresses(wallet_obj=wallet_obj)

    return dump_all_addresses(wallet_obj=wallet_obj)


def wallet_home(wallet_obj, show_welcome_msg=True):
    '''
    Loaded on bootup (and likely never again)
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    if show_welcome_msg:
        if wallet_obj.private_key is None:
            puts("You've opened your wallet in PUBLIC key mode, so you CANNOT sign transactions.")
        else:
            puts("You've opened your wallet in PRIVATE key mode, so you CAN sign transactions.")
            puts("If you like, you can always open your wallet in PUBLIC key mode like this:")
            with indent(2):
                puts(colored.magenta('$ bwallet --wallet=%s' % mpub))

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
                coin_symbol=coin_symbol_from_mkey(mpub),
                subchain_indices=[0, 1],  # for internal and change addresses
                )

        # Display balance info
        display_balance_info(wallet_obj=wallet_obj)

    # Go to home screen
    while True:
        puts('-'*75)
        puts('What do you want to do?:')
        with indent(2):
            puts(colored.cyan('1: Show new receiving addresses'))
            puts(colored.cyan('2: Show recent transactions'))
            puts(colored.cyan('3: Send funds (generate transaction, sign, & broadcast)'))
            puts(colored.cyan('4: Sweep funds into bwallet from a private key you hold'))
            puts(colored.cyan('5: Generate transaction for offline signing'))
            puts(colored.cyan('6: Broadcast transaction previously signed offline'))

        if wallet_obj.private_key:
            with indent(2):
                puts(colored.cyan('0: Dump private keys and addresses (advanced users only)'))
        else:
            with indent(2):
                puts(colored.cyan('0: Dump addresses (advanced users only)'))

        choice = choice_prompt(user_prompt=DEFAULT_PROMPT,
                acceptable_responses=range(0, 6+1))
        verbose_print('Choice: %s' % choice)

        if choice == '1':
            display_new_receiving_addresses(wallet_obj=wallet_obj)
        elif choice == '2':
            display_recent_txs(wallet_obj=wallet_obj)
        elif choice == '3':
            send_funds(wallet_obj=wallet_obj)
        elif choice == '4':
            sweep_funds_from_privkey(wallet_obj=wallet_obj)
        elif choice == '5':
            generate_offline_tx(wallet_obj=wallet_obj)
        elif choice == '6':
            broadcast_signed_tx(wallet_obj=wallet_obj)
        elif choice == '0':
            if wallet_obj.private_key:
                dump_private_keys(wallet_obj=wallet_obj)
            else:
                dump_addresses(wallet_obj)


def cli():

    parser = argparse.ArgumentParser(
        description='''
    Simple BIP32 HD cryptocurrecy command line wallet supporting BTC, BTC Testnet, Litecoin, & Dogecoin.

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
            help='Blockcypher API Key to use. If not supplied the default will be used.',
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
    try:
        get_blockchain_overview()
        USER_ONLINE = True
    except Exception as e:
        verbose_print(e)

    puts(colored.green("Welcome to bwallet!"))

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
        puts('')
        puts("You've opened your wallet without specifying a master public or master private key. Let's generate a new master private key (locally) for you to use.")
        puts('')
        puts('Which currency do you want to create a wallet for?')
        coin_symbol = coin_symbol_chooser()
        verbose_print(coin_symbol)
        network = COIN_SYMBOL_TO_BMERCHANT_NETWORK[coin_symbol]

        puts("Let's add some extra entropy in case you're on a fresh boot of a virtual machine, or your random number generator has been compromised by an unnamed three letter agency. Please bang on the keyboard for as long as you like and then hit enter. There's no reason to record this value, it cannot be used to recover your keys.")
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
        puts(colored.green('Your master PRIVATE key is: %s (guard this CAREFULLY as it can be used to steal your funds)' % mpriv))
        puts(colored.green('Your master PUBLIC key is: %s' % mpub))
        puts('')
        puts('bwallet will now quit. Open your new wallet anytime like this:')
        puts('')
        with indent(4):
            puts(colored.magenta('$ bwallet --wallet=%s' % mpriv))
        puts('')
        puts("You may also open your wallet like this (useful if you'd like to encrypt your master private key and/or don't want it in your bash history):")
        puts('')
        with indent(4):
            puts(colored.magenta('$ echo %s | bwallet' % mpriv))


if __name__ == '__main__':
    '''
    For (rare) invocation like this:
    python bwallet.py
    '''
    cli()
