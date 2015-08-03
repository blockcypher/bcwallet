# -*- coding: utf-8 -*-

import click

# bitmerchant
from bitmerchant.wallet import Wallet
from bitmerchant.wallet.keys import PrivateKey

from blockcypher import (create_hd_wallet, get_wallet_details,
        create_unsigned_tx, get_input_addresses, make_tx_signatures,
        broadcast_signed_transaction, get_blockchain_overview,
        get_total_balance)
from blockcypher.utils import (is_valid_address_for_coinsymbol,
        satoshis_to_btc, get_blockcypher_walletname_from_mpub,
        coin_symbol_from_mkey, COIN_SYMBOL_LIST)
from blockcypher.constants import COIN_SYMBOL_MAPPINGS

from utils import (guess_network_from_mkey, find_hexkeypairs_from_bip32key_bc,
        get_tx_url, hexkeypair_list_to_dict, print_without_rounding,
        COIN_SYMBOL_TO_BMERCHANT_NETWORK)

from datetime import datetime

import json


# Globals that can be overwritten at startup
VERBOSE_MODE = False
USER_ONLINE = False
# For all bwallet users:
BLOCKCYPHER_API_KEY = '9c339f92713518492a4504c273d1d9f9'


class DateTimeEncoder(json.JSONEncoder):
    # http://stackoverflow.com/a/27058505/1754586
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()

        return json.JSONEncoder.default(self, o)


def verbose_print(to_print):
    if VERBOSE_MODE:
        if type(to_print) is dict:
            to_print = json.dumps(to_print, cls=DateTimeEncoder, indent=2)
        click.secho(str(to_print), fg='yellow')


def get_public_wallet_url(mpub):
    # subchain indices set at 0 * 1
    return 'https://live.blockcypher.com/%s/xpub/%s/0-1/' % (
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

    click.echo('-' * 50)
    click.secho('Total Received: %s' % wallet_details['total_received'],
            bg='white')
    click.secho('Total Sent: %s' % wallet_details['total_sent'],
            bg='white')
    click.secho('Balance: %s' % wallet_details['final_balance'], bg='white')
    if wallet_details['unconfirmed_n_tx']:
        click.secho('Transactions: %s (%s Unconfirmed)' % (
            wallet_details['final_n_tx'],
            wallet_details['unconfirmed_n_tx'],
            ), bg='white')
    else:
        click.secho('Transactions: %s' % wallet_details['final_n_tx'],
                bg='white')

    click.secho('For details, see: %s' % get_public_wallet_url(mpub), fg='blue')

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
        click.echo('Blockcypher connection needed to see which addresses have been used.', fg='red')
        click.echo('You may dump all your addresses while offline by selecting option 0.')
        return

    mpub = wallet_obj.serialize_b58(private=False)

    unused_receiving_addresses = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=5,
            )

    click.echo('-' * 75)
    click.echo('Next 5 Unused %s Receiving Addresses (for people to send you funds):' %
            COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev']
            )

    for unused_receiving_address in unused_receiving_addresses:
        click.echo('  %s (path is %s)' % (
            unused_receiving_address['address'],
            unused_receiving_address['path'],
            ))


def display_recent_txs(wallet_obj):
    if not USER_ONLINE:
        click.echo('Blockcypher connection needed to find transactions related to your addresses.', fg='red')
        click.echo('You may dump all your addresses while offline by selecting option 0.')
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
        click.echo('No Transactions')

    txs = wallet_details.get('unconfirmed_txrefs', []) \
            + wallet_details.get('txrefs', [])
    for tx in txs:
        click.echo('Transaction %s: %s satoshis (%s %s) %s' % (
            tx.get('tx_hash'),
            tx.get('value'),
            print_without_rounding(satoshis_to_btc(tx.get('value', 0))),
            COIN_SYMBOL_MAPPINGS[coin_symbol_from_mkey(mpub)]['currency_abbrev'],
            'sent' if tx.get('tx_input_n') >= 0 else 'received',  # HACK!
            ))


def get_dest_address(coin_symbol, show_instructions=True):
    display_shortname = COIN_SYMBOL_MAPPINGS[coin_symbol]['display_shortname']
    if show_instructions:
        click.echo('What %s address do you want to send to?' % display_shortname)
    destination_address = click.prompt('฿', type=str).strip()
    if is_valid_address_for_coinsymbol(destination_address,
            coin_symbol=coin_symbol):
        return destination_address
    else:
        click.echo('Invalid %s address, try again' % display_shortname)
        return get_dest_address(coin_symbol=coin_symbol,
                show_instructions=False)


def send_funds(wallet_obj):
    if not USER_ONLINE:
        click.echo('Blockcypher connection needed to fetch unspents and broadcast signed transaction.', fg='red')
        click.echo('You may dump all your addresses and private keys while offline by selecting option 0.')
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

    destination_address = get_dest_address(coin_symbol=coin_symbol,
            show_instructions=True)

    VALUE_PROMPT = 'Your current balance is %s (in satoshis). How much do you want to send?' % (
            wallet_details['balance'])
    click.echo(VALUE_PROMPT)
    dest_satoshis = click.prompt('฿', type=click.IntRange(1,
        wallet_details['balance']))

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

    verbose_print('Inputs:')
    verbose_print(inputs)
    verbose_print('Outputs:')
    verbose_print(outputs)
    verbose_print('Change Address: %s' % change_address)
    verbose_print('coin symbol: %s' % coin_symbol)

    unsigned_tx = create_unsigned_tx(
        inputs=inputs,
        outputs=outputs,
        change_address=change_address,
        coin_symbol=coin_symbol,
        verify_tosigntx=True,  # guarantees we are signing the right TX
        )

    verbose_print('Unsigned TX:')
    verbose_print(unsigned_tx)

    if 'errors' in unsigned_tx:
        print('TX Error(s): Tx NOT Signed or Broadcast')
        for error in unsigned_tx['errors']:
            print(error['error'])
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

    CONF_TEXT = 'Send %s satoshis (%s %s) to %s' % (
            dest_satoshis,
            print_without_rounding(satoshis_to_btc(dest_satoshis)),
            COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
            destination_address,
            )

    if not click.confirm(CONF_TEXT, default=True):
        click.echo('Transaction Not Broadcast!')
        return

    broadcasted_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            pubkeys=pubkeyhex_list,
            coin_symbol=coin_symbol,
    )
    verbose_print('Broadcast TX Details:')
    verbose_print(broadcasted_tx)

    tx_url = get_tx_url(
            tx_hash=broadcasted_tx['tx']['hash'],
            coin_symbol=coin_symbol,
            )
    click.echo('Transaction %s Broadcast' % broadcasted_tx['tx']['hash'])
    click.echo(tx_url, fg='blue')

    # Display updated wallet balance info
    display_balance_info(wallet_obj=wallet_obj)


def generate_offline_tx(wallet_obj):
    # TODO: implement
    click.echo('Feature Coming Soon')


def broadcast_signed_tx(wallet_obj):
    # TODO: implement
    click.echo('Feature Coming Soon')


def get_wif_obj(network, show_instructions=True):
    if show_instructions:
        click.echo('Enter a private key (in WIF format) to send from?')

    wif = click.prompt('฿', type=str).strip()
    verbose_print(wif)
    try:
        return PrivateKey.from_wif(wif, network=network)
    except Exception as e:
        verbose_print(e)
        click.echo('Invalid WIF %s, Please Try Again' % wif)
        get_wif_obj(network=network, show_instructions=False)


def sweep_funds_from_privkey(wallet_obj):
    if not USER_ONLINE:
        click.echo('Blockcypher connection needed to fetch unspents and broadcast signed transaction.', fg='red')
        return

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = str(coin_symbol_from_mkey(mpub))
    network = guess_network_from_mkey(mpub)

    wif_obj = get_wif_obj(network, show_instructions=True)

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
        verify_tosigntx=True,  # guarantees we are signing the right TX
        )
    verbose_print('Unsigned TX:')
    verbose_print(unsigned_tx)

    if 'errors' in unsigned_tx:
        print('TX Error(s): Tx NOT Signed or Broadcast')
        for error in unsigned_tx['errors']:
            print(error['error'])
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

    click.echo(broadcasted_tx['tx']['hash'])
    tx_url = get_tx_url(
            tx_hash=broadcasted_tx['tx']['hash'],
            coin_symbol=coin_symbol,
            )
    click.echo(tx_url)

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

        click.echo('  %s (%s/%s) - %s satoshis (%s %s)' % (
                path_display,
                address,
                wif,
                addr_balance,
                print_without_rounding(satoshis_to_btc(addr_balance)),
                COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
                ))
    else:
        click.echo('  %s (%s/%s)' % (
                path_display,
                address,
                wif,
                ))


def dump_all_keys(wallet_obj):

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)

    click.echo('How many private keys (on each chain) do you want to dump?')
    num_keys = click.prompt('฿', type=click.IntRange(1, 10**5), default=5,
            show_default=False)

    click.echo('-'*50)
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    click.echo('External Chain:')
                elif chain_int == 1:
                    click.echo('Internal Chain:')
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
        click.echo('Which private keys do you want?')
        click.echo(' 1: All private keys (regardless of whether they have funds to spend)')
        click.echo(' 2: Active private keys (those with funds to spend)')
        choice = click.prompt('฿', type=click.IntRange(1, 2), default=1,
                show_default=False)
        if choice == 1:
            return dump_all_keys(wallet_obj=wallet_obj)
        elif choice == 2:
            return dump_active_keys(wallet_obj=wallet_obj)

    return dump_all_keys(wallet_obj=wallet_obj)


def dump_all_addresses(wallet_obj):
    '''
    Offline-enabled mechanism to dump addresses
    '''

    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = coin_symbol_from_mkey(mpub)

    click.echo('How many addresses (on each chain) do you want to dump?')
    num_keys = click.prompt('฿', type=click.IntRange(1, 10**5), default=5,
            show_default=False)

    click.echo('-'*50)
    for chain_int in (0, 1):
        for current in range(0, num_keys):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    click.echo('External Chain Addresses:')
                elif chain_int == 1:
                    click.echo('Internal Chain Addresses:')
                click.echo('  address (path)')
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

            click.echo('  %s (%s) - %s satoshis (%s %s)' % (
                    address,
                    path_display,
                    addr_balance,
                    print_without_rounding(satoshis_to_btc(addr_balance)),
                    COIN_SYMBOL_MAPPINGS[coin_symbol]['currency_abbrev'],
                    ))
        else:
            click.echo('  %s (%s)' % (
                    address,
                    path_display,
                    ))


def dump_active_addresses(wallet_obj):
    click.echo('Displaying Public Addresses Only')
    click.echo('For Private Keys, please open bwallet with your Master Private Key:')
    click.echo('  $ bwallet --wallet=xpriv123...')

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
        click.echo('Which addresses do you want?')
        click.echo(' 1: All addresses (regardless of whether they have funds to spend)')
        click.echo(' 2: Active addresses (those with funds to spend)')
        choice = click.prompt('฿', type=click.IntRange(1, 2), default=1,
                show_default=False)
        if choice == 1:
            return dump_all_addresses(wallet_obj=wallet_obj)
        elif choice == 2:
            return dump_active_addresses(wallet_obj=wallet_obj)

    return dump_all_addresses(wallet_obj=wallet_obj)


def wallet_home(wallet_obj, show_welcome_msg=True):
    '''
    Loaded on bootup (and likely never again)
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    if show_welcome_msg:
        if wallet_obj.private_key is None:
            click.echo("You've opened your wallet in PUBLIC key mode, so you CANNOT sign transactions.")
        else:
            click.echo("You've opened your wallet in PRIVATE key mode, so you CAN sign transactions.")
            click.echo("If you like, you can always open your wallet in PUBLIC key mode like this:")
            click.echo('  $ bwallet --wallet=%s' % mpub)

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
        click.echo('-'*75)
        click.echo('What do you want to do?:')
        click.echo(' 1: Show new receiving addresses')
        click.echo(' 2: Show recent transactions')
        click.echo(' 3: Send funds (generate transaction, sign, & broadcast)')
        click.echo(' 4: Sweep funds into bwallet from a private key you hold')
        click.echo(' 5: Generate transaction for offline signing')
        click.echo(' 6: Broadcast transaction previously signed offline')
        if wallet_obj.private_key:
            click.echo(' 0: Dump private keys and addresses (advanced users only)')
        else:
            click.echo(' 0: Dump addresses (advanced users only)')
        choice = click.prompt('฿', type=click.IntRange(0, 6))

        if choice == 1:
            display_new_receiving_addresses(wallet_obj=wallet_obj)
        elif choice == 2:
            display_recent_txs(wallet_obj=wallet_obj)
        elif choice == 3:
            send_funds(wallet_obj=wallet_obj)
        elif choice == 4:
            sweep_funds_from_privkey(wallet_obj=wallet_obj)
        elif choice == 5:
            generate_offline_tx(wallet_obj=wallet_obj)
        elif choice == 6:
            broadcast_signed_tx(wallet_obj=wallet_obj)
        elif choice == 0:
            if wallet_obj.private_key:
                dump_private_keys(wallet_obj=wallet_obj)
            else:
                dump_addresses(wallet_obj)


def coin_symbol_chooser():
    click.echo('Which currency do you want to create a wallet for?')
    for cnt, coin_symbol_choice in enumerate(COIN_SYMBOL_LIST):
        click.secho('%s: %s' % (
            cnt+1,
            COIN_SYMBOL_MAPPINGS[coin_symbol_choice]['display_name'],
            ), fg='cyan')
    coin_symbol_int = click.prompt('฿',
            type=click.IntRange(1, len(COIN_SYMBOL_LIST)))
    verbose_print(coin_symbol_int)

    return COIN_SYMBOL_LIST[coin_symbol_int-1]


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--wallet', help='Master private or public key (starts with xprv and xpub for BTC)')
@click.option('--bc-api-key', help='Blockcypher API Key to use. If not supplied the default will be used.')
@click.option('--verbose', is_flag=True, help='Show detailed logging info.', default=False)
@click.version_option()
def cli(wallet, bc_api_key, verbose):
    '''
    Simple cryptocurrecy command line wallet.

    Keys are generated and transactions are signed locally for trustless use. Blockchain heavy lifting powered by BlockCypher.
    '''

    if verbose:
        global VERBOSE_MODE
        VERBOSE_MODE = True

    if bc_api_key:
        global BLOCKCYPHER_API_KEY
        verbose_print('API Key: %s' % BLOCKCYPHER_API_KEY)
        BLOCKCYPHER_API_KEY = bc_api_key

    # Check if blockcypher is up (basically if the user's machine is online)
    global USER_ONLINE
    try:
        get_blockchain_overview()
        USER_ONLINE = True
    except Exception as e:
        verbose_print(e)

    verbose_print('wallet %s' % wallet)

    click.secho("Welcome to bwallet!", fg='green')

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
                        click.echo("Invalid entry: %s" % wallet, fg='red')
            except IndexError:
                click.secho("Invalid entry: %s" % wallet, fg='red')

            # Run the program:
            return wallet_home(wallet_obj)

        else:
            click.echo("Invalid wallet entry: %s" % wallet)

    else:
        click.echo("You've opened your wallet without specifying a master public or master private key. Let's generate a new master private key (locally) for you to use.")

        coin_symbol = coin_symbol_chooser()
        network = COIN_SYMBOL_TO_BMERCHANT_NETWORK[coin_symbol]

        click.echo("Let's add some extra entropy in case you're on a fresh boot of a virtual machine, or your random number generator has been compromised by an unnamed three letter agency. Please bang on the keyboard for as long as you like and then hit enter. There's no reason to record this value, it cannot be used to recover your keys.")
        extra_entropy = click.prompt("฿ (optional)", hide_input=True)

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
        click.echo('Your master PRIVATE key is: %s' % mpriv)
        click.echo('Your master PUBLIC key is: %s' % mpub)
        click.echo('bwallet will now quit. Open your new wallet anytime like this:')
        click.echo('')
        click.echo('    $ bwallet --wallet=%s' % mpriv)
        click.echo('')


if __name__ == '__main__':
    '''
    For (rare) invocation like this:
    python bwallet.py
    '''
    cli()
