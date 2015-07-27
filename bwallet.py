# -*- coding: utf-8 -*-

import click

# bitmerchant
from bitmerchant.wallet import Wallet
from bitmerchant.wallet.keys import PrivateKey

from blockcypher import (create_hd_wallet, get_wallet_details,
        create_unsigned_tx, get_input_addresses, make_tx_signatures,
        broadcast_signed_transaction)
from blockcypher.utils import is_valid_address_for_coinsymbol, satoshis_to_btc
from blockcypher.constants import COIN_SYMBOL_MAPPINGS

from utils import (guess_network_from_mkey, guess_cs_from_mkey,
        find_hexkeypair_from_bip32key_bc, find_paths_from_bip32key_bc,
        get_blockcypher_walletname_from_mpub, get_tx_url,
        COIN_SYMBOL_TO_BMERCHANT_NETWORK, COIN_SYMBOL_LIST)


# FIXME: use a public API key that can be stored in source code
with open('.env', 'r') as f:
    import json
    BLOCKCYPHER_PUBLIC_API_KEY = json.loads(f.read())['BLOCKCYPHER_PUBLIC_API_KEY']
assert BLOCKCYPHER_PUBLIC_API_KEY


def display_balance_info(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)

    bc_wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indexes=[0, 1],
            )
    if verbose:
        print('Wallet Name: %s' % bc_wallet_name)
        print('API Key: %s' % BLOCKCYPHER_PUBLIC_API_KEY)

    wallet_details = get_wallet_details(
            wallet_name=bc_wallet_name,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),  # FIXME: fails for BCY!
            )
    click.echo('-' * 50)
    click.echo('Total Received: %s' % wallet_details['total_received'])
    click.echo('Total Sent: %s' % wallet_details['total_sent'])
    click.echo('Balance: %s' % wallet_details['final_balance'])
    if wallet_details['unconfirmed_n_tx']:
        click.echo('Transactions: %s (%s Unconfirmed)' % (
            wallet_details['final_n_tx'],
            wallet_details['unconfirmed_n_tx'],
            ))
    else:
        click.echo('Transactions: %s' % wallet_details['final_n_tx'])

    return


def get_used_addresses(wallet_obj, verbose=False):
    '''
    Get addresses already used by the wallet
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indexes=[0, 1],
            )

    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),  # FIXME: fails for BCY!
            )

    if verbose:
        print(wallet_details)

    return set(wallet_details['wallet']['addresses'])


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


def get_unused_receiving_addresses(wallet_obj, num_addrs_to_return=5,
        verbose=False):
    used_addr_set = get_used_addresses(wallet_obj=wallet_obj, verbose=verbose)
    return get_unused_addresses_on_subchain(
            wallet_obj=wallet_obj,
            subchain_index=0,  # external chain
            num_addrs_to_return=num_addrs_to_return,
            used_addr_set=used_addr_set,
            )


def get_unused_change_addresses(wallet_obj, num_addrs_to_return=1,
        verbose=False):
    used_addr_set = get_used_addresses(wallet_obj=wallet_obj, verbose=verbose)
    return get_unused_addresses_on_subchain(
            wallet_obj=wallet_obj,
            subchain_index=1,  # internal chain
            num_addrs_to_return=num_addrs_to_return,
            used_addr_set=used_addr_set,
            )


def display_new_receiving_addresses(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)

    click.echo('-' * 75)
    click.echo('Next 5 Unused %s Recieving Addresses (for people to send you funds):' %
            COIN_SYMBOL_MAPPINGS[guess_cs_from_mkey(mpub)]['currency_abbrev']
            )

    unused_receiving_addresses = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=5,
            verbose=verbose,
            )

    for unused_receiving_address in unused_receiving_addresses:
        click.echo('  %s (path is %s)' % (
            unused_receiving_address['address'],
            unused_receiving_address['path'],
            ))
    # TODO: add option for when there is no internet connection
    # Just tells you to use the advanced settings to dump

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
        show_instructions=True)


def display_recent_txs(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)
    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indexes=[0, 1],
            )

    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),  # FIXME: fails for BCY!
            )

    # TODO: pagination for lots of transactions
    if not wallet_details.get('txrefs'):
        click.echo('No Transactions')

    txs = wallet_details.get('unconfirmed_txrefs', []) \
            + wallet_details.get('txrefs', [])
    for tx in txs:
        click.echo('Transaction %s: %s satoshis (%s %s) %s' % (
            tx.get('tx_hash'),
            tx.get('value'),
            satoshis_to_btc(tx.get('value', 0)),
            COIN_SYMBOL_MAPPINGS[guess_cs_from_mkey(mpub)]['currency_abbrev'],
            'sent' if tx.get('tx_input_n') >= 0 else 'received',  # HACK!
            ))

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
        show_instructions=True)


def send_funds(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)
    mpriv = wallet_obj.serialize_b58(private=True)

    coin_symbol = str(guess_cs_from_mkey(mpub))

    if verbose:
        print(coin_symbol)

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indexes=[0, 1],
            )
    wallet_details = get_wallet_details(
            wallet_name=wallet_name,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=coin_symbol,
            )

    DEST_PROMPT = 'What address do you want to send to?'
    destination_address = click.prompt(DEST_PROMPT, type=str)
    while not is_valid_address_for_coinsymbol(destination_address,
            coin_symbol=coin_symbol):
        destination_address = click.prompt('Invalid address, try again',
                type=int)

    VALUE_PROMPT = 'How much (in satoshis) do you want to send? Current balance is %s' % (
            wallet_details['balance'])
    dest_satoshis = click.prompt(VALUE_PROMPT, type=int)

    # TODO: confirm value entered
    # TODO: add ability to set preference

    inputs = [{
            'wallet_name': wallet_name,
            'wallet_token': BLOCKCYPHER_PUBLIC_API_KEY,
            }, ]
    outputs = [{
            'value': dest_satoshis,
            'address': destination_address,
            }, ]

    change_address = get_unused_change_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=1,
            verbose=verbose,
            )[0]['address']

    if verbose:
        print('Inputs:')
        print(json.dumps(inputs, indent=2))
        print('Outputs:')
        print(json.dumps(outputs, indent=2))
        print('Change Address: %s' % change_address)
        print('coin symbol: %s' % coin_symbol)

    unsigned_tx = create_unsigned_tx(
        inputs=inputs,
        outputs=outputs,
        change_address=change_address,
        coin_symbol=coin_symbol,
        verify_tosigntx=True,  # guarantees we are signing the right TX
        )

    if verbose:
        print('Unsigned TX:')
        print(json.dumps(unsigned_tx, indent=2))

    privkeyhex_list, pubkeyhex_list = [], []
    for input_address in get_input_addresses(unsigned_tx):
        hexkey_dict = find_hexkeypair_from_bip32key_bc(
            pub_address=input_address,
            master_key=mpriv,
            network=guess_network_from_mkey(mpriv),  # FIXME: support all coins
            )

        err_msg = "Couldn't find %s traversing bip32 key" % input_address
        assert hexkey_dict['privkeyhex'], err_msg

        privkeyhex_list.append(hexkey_dict['privkeyhex'])
        pubkeyhex_list.append(hexkey_dict['pubkeyhex'])

    if verbose:
        print('Private Key List: %s' % privkeyhex_list)
        print('Public Key List: %s' % pubkeyhex_list)

    # sign locally
    tx_signatures = make_tx_signatures(
            txs_to_sign=unsigned_tx['tosign'],
            privkey_list=privkeyhex_list,
            pubkey_list=pubkeyhex_list,
            )

    if verbose:
        print('TX Signatures: %s' % tx_signatures)

    # FIXME: add final confirmation before broadcast

    broadcasted_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            pubkeys=pubkeyhex_list,
            coin_symbol=coin_symbol,
    )

    if verbose:
        print('Broadcasted TX')
        print(json.dumps(broadcasted_tx, indent=2))

    click.echo(broadcasted_tx['tx']['hash'])

    tx_url = get_tx_url(
            tx_hash=broadcasted_tx['tx']['hash'],
            coin_symbol=coin_symbol,
            )
    click.echo(tx_url)

    # Display updated wallet balance info
    display_balance_info(wallet_obj=wallet_obj, verbose=verbose)

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
            show_instructions=True)


def generate_offline_tx(wallet_obj, verbose=False):
    pass


def sweep_funds_from_privkey(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)
    coin_symbol = str(guess_cs_from_mkey(mpub))

    pkey = click.prompt('Enter a private key (in WIF format) to send from?',
            type=str)
    # TODO: error checking if invalid wif
    pkey_obj = PrivateKey.from_wif(pkey, network=guess_network_from_mkey(mpub))
    pkey_addr = pkey_obj.get_public_key().to_address(compressed=True)

    if verbose:
        click.echo('%s from %s' % (pkey_addr, pkey))

    # FIXME: sign and broadcast tx

    inputs = [{
            'address': pkey_addr,
            }, ]

    dest_addr = get_unused_receiving_addresses(
            wallet_obj=wallet_obj,
            num_addrs_to_return=1,
            verbose=verbose,
            )[0]['address']

    outputs = [{
            'address': dest_addr,
            'value': -1,  # sweep value
            }, ]

    unsigned_tx = create_unsigned_tx(
        inputs=inputs,
        outputs=outputs,
        change_address=None,
        coin_symbol=coin_symbol,
        verify_tosigntx=True,  # guarantees we are signing the right TX
        )

    if verbose:
        print('Unsigned TX:')
        print(json.dumps(unsigned_tx, indent=2))

    privkeyhex_list, pubkeyhex_list = [], []
    for _ in unsigned_tx['tx']['inputs']:
        privkeyhex_list.append(pkey_obj.get_key())
        pubkeyhex_list.append(pkey_obj.get_public_key().get_key(
            compressed=True))

    if verbose:
        print('Private Key List: %s' % privkeyhex_list)
        print('Public Key List: %s' % pubkeyhex_list)

    # sign locally
    tx_signatures = make_tx_signatures(
            txs_to_sign=unsigned_tx['tosign'],
            privkey_list=privkeyhex_list,
            pubkey_list=pubkeyhex_list,
            )

    if verbose:
        print('TX Signatures: %s' % tx_signatures)

    # FIXME: verify what is being signed is legit
    # FIXME: add final confirmation before broadcast

    broadcasted_tx = broadcast_signed_transaction(
            unsigned_tx=unsigned_tx,
            signatures=tx_signatures,
            pubkeys=pubkeyhex_list,
            coin_symbol=coin_symbol,
    )

    if verbose:
        print('Broadcasted TX')
        print(json.dumps(broadcasted_tx, indent=2))

    click.echo(broadcasted_tx['tx']['hash'])
    tx_url = get_tx_url(
            tx_hash=broadcasted_tx['tx']['hash'],
            coin_symbol=coin_symbol,
            )
    click.echo(tx_url)

    # Display updated wallet balance info
    display_balance_info(wallet_obj=wallet_obj, verbose=verbose)

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
            show_instructions=True)


def dump_private_keys(wallet_obj, verbose=False):
    '''
    Offline mechanism to dump everything
    '''

    # TODO: pagination

    click.echo('-'*50)
    for chain_int in (0, 1):
        for current in range(0, 10):
            path = "m/%d/%d" % (chain_int, current)
            if current == 0:
                if chain_int == 0:
                    click.echo('External Chain Addresses:')
                elif chain_int == 1:
                    click.echo('Internal Chain Addresses:')
                click.echo('  path,WIF,address')
            child_wallet = wallet_obj.get_child_for_path(path)
            click.echo('  %s,%s,%s' % (
                path,
                child_wallet.export_to_wif(),
                child_wallet.to_address(),
                ))

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
        show_instructions=True)


def dump_active_addresses(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)

    click.echo('Displaying Public Addresses Only')
    click.echo('For Private Keys, please open bwallet with your Master Private Key:')
    click.echo('  $ bwallet --wallet=xpriv123...')

    used_addresses = list(get_used_addresses(wallet_obj=wallet_obj,
            verbose=verbose))

    # get active addresses
    paths = find_paths_from_bip32key_bc(
            pub_address_list=used_addresses,
            master_key=mpub,
            network=guess_network_from_mkey(mpub),
            starting_pos=0,
            depth=100,  # TODO: pagination
            )

    for cnt, used_addr in enumerate(used_addresses):
        path_display = paths[cnt]
        if not path_display:
            path_display = 'deeper traversal needed'
        click.echo('  %s (%s) - %s (%s)' % (
                used_addr,
                path_display,
                # FIXME:
                '0 satoshis',
                '0 BTC',
                ))

    # TODO: add boolean for whether or not they have a balance (if online)

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
        show_instructions=True)


def wallet_home_chooser(wallet_obj, verbose=False, show_instructions=True):
    '''
    Home menu selector for what to do
    '''
    # TODO: change options based on whether or not we're online

    if show_instructions:
        click.echo('-'*75)
        click.echo('What do you want to do?:')
        click.echo(' 1: Get new receiving addresses')
        click.echo(' 2: Show recent transactions')
        if wallet_obj.private_key:
            click.echo(' 3: Send funds (generate transaction, sign, & broadcast)')
        else:
            click.echo(' 3: Generate transaction for offline signing')
        click.echo(' 4: Sweep funds into bwallet from a private key you hold')
        if wallet_obj.private_key:
            click.echo(' 0: Dump private keys (advanced users only)')
        else:
            click.echo(' 0: Dump active addresses (advanced users only)')
    choice = click.prompt('฿', type=int)

    if choice == 1:
        return display_new_receiving_addresses(wallet_obj=wallet_obj,
                verbose=verbose)
    elif choice == 2:
        return display_recent_txs(wallet_obj=wallet_obj, verbose=verbose)
    elif choice == 3:
        if wallet_obj.private_key:
            return send_funds(wallet_obj=wallet_obj, verbose=verbose)
        else:
            return generate_offline_tx(wallet_obj=wallet_obj, verbose=verbose)
    elif choice == 4:
        return sweep_funds_from_privkey(wallet_obj=wallet_obj, verbose=verbose)
    elif choice == 0:
        if wallet_obj.private_key:
            return dump_private_keys(wallet_obj=wallet_obj, verbose=verbose)
        else:
            return dump_active_addresses(wallet_obj, verbose=verbose)
    else:
        return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
                show_instructions=False)


def wallet_home(wallet_obj, verbose=False, show_welcome_msg=True):
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

    wallet_name = get_blockcypher_walletname_from_mpub(
            mpub=mpub,
            subchain_indexes=[0, 1],
            )

    # Instruct blockcypher to track the wallet by pubkey
    create_hd_wallet(
            wallet_name=wallet_name,
            xpubkey=mpub,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),
            subchain_indexes=[0, 1],  # for internal and change addresses
            )

    # Display balance info
    display_balance_info(wallet_obj=wallet_obj, verbose=verbose)

    # Go to home screen
    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
            show_instructions=True)


def coin_symbol_chooser(verbose=False):
    click.echo('Which currency do you want to create a wallet for?')
    for coin_symbol_choice in COIN_SYMBOL_LIST:
        click.echo('  %s: %s' % (
            coin_symbol_choice,
            COIN_SYMBOL_MAPPINGS[coin_symbol_choice]['display_name'],
            ))
    coin_symbol = click.prompt('฿').lower()
    if verbose:
        click.echo(coin_symbol)
    if coin_symbol in COIN_SYMBOL_LIST:
        return coin_symbol
    else:
        click.echo('`%s` is not a valid entry' % coin_symbol)
        return coin_symbol_chooser()


@click.command()
@click.option('--wallet', help='Master public or private key (starts with xprv... and xpub... for BTC)')
@click.option('--verbose', is_flag=True, default=False)
def cli(wallet, verbose):
    '''
    Simple cryptocurrecy command line wallet.

    Keys are generated and transactions are signed locally. Blockchain heavy lifting powered by blockcyper.
    '''

    if verbose:
        click.echo('wallet %s' % wallet)

    click.echo("Welcome to bwallet!")

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
                        click.echo("Invalid entry: %s" % wallet)
            except IndexError:
                click.echo("Invalid entry: %s" % wallet)

            # Run the program:
            return wallet_home(wallet_obj, verbose=verbose)

        else:
            click.echo("Invalid wallet entry: %s" % wallet)

    else:
        click.echo("You've opened your wallet without specifying a master public or master private key. Let's generate a new master private key (locally) for you to use.")

        coin_symbol = coin_symbol_chooser(verbose=verbose)
        network = COIN_SYMBOL_TO_BMERCHANT_NETWORK[coin_symbol]

        click.echo("Let's add some extra entropy in case you're on a fresh boot of a virtual machine, or your random number generator has been compromised.")
        click.echo("Please bang on the keyboard for as long as you like.")
        click.echo("There's no reason to record this value, it cannot be used to recover your keys")
        extra_entropy = click.prompt("฿")

        if verbose:
            click.echo(extra_entropy)
            # worst-case assumption (attacker knows keyspace and length)
            entropy_space = len(extra_entropy) ** len(set(extra_entropy))
            bits_entropy = len(bin(entropy_space)) - 2
            click.echo('bits of extra_entropy: %s' % bits_entropy)

        user_wallet_obj = Wallet.new_random_wallet(network=network,
                user_entropy=extra_entropy)
        mpriv = user_wallet_obj.serialize_b58(private=True)
        mpub = user_wallet_obj.serialize_b58(private=False)
        click.echo('Your master PRIVATE key is: %s' % mpriv)
        click.echo('Your master PUBLIC key is: %s' % mpub)
        click.echo('bwallet will now quit. Open your new wallet anytime like this:')
        click.echo('    $ bwallet --wallet=%s' % mpriv)


if __name__ == '__main__':
    '''
    For (rare) invocation like this:
    python bwallet.py
    '''
    cli()
