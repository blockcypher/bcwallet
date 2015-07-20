import click
#from clint.textui import click.echo, indent, prompt
#from clint import arguments

# bitmerchant
from bitmerchant.wallet import Wallet
from bitmerchant.wallet.keys import PrivateKey

from blockcypher import (create_hd_wallet, get_wallet_details,
        create_unsigned_tx, get_input_addresses, make_tx_signatures,
        broadcast_signed_transaction)
from blockcypher.utils import is_valid_address_for_coinsymbol, satoshis_to_btc
from blockcypher.constants import COIN_SYMBOL_MAPPINGS

from utils import (guess_network_from_mkey, guess_cs_from_mkey,
        find_hexkeys_from_bip32masterkey, get_blockcypher_walletname_from_mpub)


# FIXME: use a public API key that can be stored in source code
with open('.env', 'r') as f:
    import json
    BLOCKCYPHER_PUBLIC_API_KEY = json.loads(f.read())['BLOCKCYPHER_PUBLIC_API_KEY']
assert BLOCKCYPHER_PUBLIC_API_KEY


def display_balance_info(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)

    bc_wallet_name = get_blockcypher_walletname_from_mpub(mpub)
    if verbose:
        print('Wallet Name: %s' % bc_wallet_name)

    wallet_details = get_wallet_details(
            wallet_name=bc_wallet_name,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),  # FIXME: fails for BCY!
            )
    click.echo('-' * 50)
    click.echo('Total Received: %s' % wallet_details['total_received'])
    click.echo('Total Sent: %s' % wallet_details['total_sent'])
    click.echo('Balance: %s' % wallet_details['final_balance'])
    click.echo('Transactions: %s (%s Unconfirmed)' % (wallet_details['n_tx'],
        wallet_details['unconfirmed_n_tx']))

    return


def display_new_receiving_addresses(wallet_obj, verbose=False):
    pass


def display_recent_txs(wallet_obj, verbose=False):
    mpub = wallet_obj.serialize_b58(private=False)
    bc_wallet_name = get_blockcypher_walletname_from_mpub(mpub)

    wallet_details = get_wallet_details(
            wallet_name=bc_wallet_name,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),  # FIXME: fails for BCY!
            )

    # TODO: pagination for lots of transactions
    if not wallet_details.get('txrefs'):
        click.echo('No Transactions')

    for tx in wallet_details.get('txrefs', []):
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

    wallet_details = get_wallet_details(
            wallet_name=get_blockcypher_walletname_from_mpub(mpub),
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
            'wallet_name': get_blockcypher_walletname_from_mpub(mpub),
            'wallet_token': BLOCKCYPHER_PUBLIC_API_KEY,
            },
            ]
    outputs = [{
            'value': dest_satoshis,
            'addresses': [destination_address, ],
            },
            ]

    if verbose:
        print('Inputs:')
        print(json.dumps(inputs, indent=2))
        print('Outputs:')
        print(json.dumps(outputs, indent=2))
        print('coin symbol: %s' % coin_symbol)

    unsigned_tx = create_unsigned_tx(
        inputs=inputs,
        outputs=outputs,
        coin_symbol=coin_symbol,
        include_tosigntx=True,
        )

    if verbose:
        print('Unsigned TX:')
        print(json.dumps(unsigned_tx, indent=2))

    privkeyhex_list, pubkeyhex_list = [], []
    for input_address in get_input_addresses(unsigned_tx):
        hexkey_dict = find_hexkeys_from_bip32masterkey(
            pub_address=input_address,
            master_key=mpriv,
            #network=foo,  # FIXME: support all coins
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

    # TODO: add nice message with link to block explorer
    click.echo(broadcasted_tx['tx']['hash'])

    # Display updated wallet balance info
    display_balance_info(wallet_obj=wallet_obj, verbose=verbose)

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
            show_instructions=True)


def generate_offline_tx(wallet_obj, verbose=False):
    pass


def sweep_funds_from_privkey(wallet_obj, verbose=False):
    pkey = click.prompt('What private key would you like to send from?',
            type=str)
    pkey_obj = PrivateKey.from_wif(pkey)
    pkey_addr = pkey_obj.get_public_key().to_address()
    pkey_hex = pkey_obj.get_key()  # used for raw signing

    # FIXME
    click.echo('To Implement')  # note sweep value == -1

    if verbose:
        click.echo('%s for %s' % (pkey_addr, pkey_hex))

    # TODO: sign and broadcast tx

    return wallet_home_chooser(wallet_obj=wallet_obj, show_instructions=True,
            verbose=verbose)


def dump_private_keys(wallet_obj, verbose=False):

    pass


def dump_active_addresses(wallet_obj, verbose=False):
    click.echo('Displaying Public Addresses Only')
    click.echo('For Private Keys, please open bmoney with your Master Private Key:')
    click.echo('  $ bmoney --wallet=xpriv123...')

    # BIP 32 Default Wallet
    # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#The_default_wallet_layout
    m0_wallet = wallet_obj.get_child(0)

    # TODO: add boolean for whether or not they have a balance (if online)
    # TODO: ability to paginate more

    click.echo('-'*50)
    click.echo('Internal Chain Addresses:')
    for x in range(10):
        curr_wallet = m0_wallet.get_child(0).get_child(x)
        path = 'm/0/0/%s' % x
        click.echo('%s (%s)' % (curr_wallet.to_address(), path))

    click.echo('-'*50)
    click.echo('External Chain Addresses:')
    for x in range(10):
        curr_wallet = m0_wallet.get_child(1).get_child(x)
        path = 'm/0/1/%s' % x
        click.echo('%s (%s)' % (curr_wallet.to_address(), path))

    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
        show_instructions=True)


def wallet_home_chooser(wallet_obj, verbose=False, show_instructions=True):
    '''
    Home menu selector for what to do
    '''
    if show_instructions:
        click.echo('-'*75)
        click.echo('Here are your options:')
        click.echo(' 1: Get new receiving addresses')
        click.echo(' 2: Show recent transactions')
        if wallet_obj.private_key:
            click.echo(' 3: Send funds (generate transaction, sign & broadcast')
        else:
            click.echo(' 3: Generate transaction for offline signing')
        click.echo(' 4: Sweep funds into bwallet from a private key you hold')
        if wallet_obj.private_key:
            click.echo(' 0: Dump private keys (advanced users only)')
        else:
            click.echo(' 0: Dump active addresses (advanced users only)')
        click.echo('')
        choice = click.prompt('What do you want to do?', type=int)
    else:
        choice = click.prompt('Invalid entry. Please choose a number 0-5', type=int)

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
        return sweep_funds_from_privkey(sweep_funds_from_privkey,
                verbose=verbose)
    elif choice == 0:
        if wallet_obj.private_key:
            return dump_private_keys(wallet_obj=wallet_obj, verbose=verbose)
        else:
            return dump_active_addresses(wallet_obj, verbose=verbose)
    else:
        return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
                show_instructions=True)


def wallet_home(wallet_obj, verbose=False, show_welcome_msg=True):
    '''
    '''
    mpub = wallet_obj.serialize_b58(private=False)

    if show_welcome_msg:
        if wallet_obj.private_key is None:
            click.echo("You've opened your wallet in PUBLIC key mode, so you cannot sign transactions.")
        else:
            click.echo("You've opened your wallet in PRIVATE key mode, so you CAN sign transactions.")
            click.echo("If you like, you can always open your wallet in PUBLIC key mode like this:")
            click.echo('  $ bmoney --wallet=%s' % mpub)

    # Instruct blockcypher to track the wallet by pubkey
    create_hd_wallet(
            wallet_name=get_blockcypher_walletname_from_mpub(mpub),
            xpubkey=mpub,
            api_key=BLOCKCYPHER_PUBLIC_API_KEY,
            coin_symbol=guess_cs_from_mkey(mpub),
            )

    # Display balance info
    display_balance_info(wallet_obj=wallet_obj, verbose=verbose)

    # Go to home screen
    return wallet_home_chooser(wallet_obj=wallet_obj, verbose=verbose,
            show_instructions=True)


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
        print('BlockCypher API Key: %s' % BLOCKCYPHER_PUBLIC_API_KEY)

    click.echo("Welcome to bmoney!")

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
        click.echo("You've opened your wallet without specifying a master public or master private key.")
        click.echo("Let's generate a new master private key (locally) for you to use")

        # TODO: add extra_entropy protection for compromised CSPRNG
        # TODO: support other coins
        user_wallet_obj = Wallet.new_random_wallet()
        mpriv = user_wallet_obj.serialize_b58(private=True)
        mpub = user_wallet_obj.serialize_b58(private=False)
        click.echo('Your master PRIVATE key is: %s' % mpriv)
        click.echo('Your master PUBLIC key is: %s' % mpub)
        click.echo('bmoney will now quit. Open your new wallet anytime like this:')
        click.echo('    $ bmoney --wallet=%s' % mpriv)


if __name__ == '__main__':
    '''
    For invocation like this:
    python bmoney.py
    '''
    cli()
