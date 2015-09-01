# -*- coding: utf-8 -*-

# Command line utilties and helper functions

from clint.textui import puts, colored, indent
from getpass import getpass

from blockcypher.utils import (is_valid_address_for_coinsymbol,
        coin_symbol_from_mkey, format_output, UNIT_CHOICES)
from blockcypher.constants import COIN_SYMBOL_MAPPINGS, COIN_SYMBOL_LIST

from bitmerchant.wallet.keys import PrivateKey

import json

from datetime import datetime


DEFAULT_PROMPT = '฿'


class DateTimeEncoder(json.JSONEncoder):
    # http://stackoverflow.com/a/27058505/1754586
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()

        return json.JSONEncoder.default(self, o)


def debug_print(to_print):
    if type(to_print) is dict:
        to_print = json.dumps(to_print, cls=DateTimeEncoder, indent=2)
    puts(colored.yellow(str(to_print)))


def choice_prompt(user_prompt=DEFAULT_PROMPT, acceptable_responses=[],
        default_input=None, show_default=True, quit_ok=False):

    assert len(acceptable_responses) > 0, acceptable_responses
    acceptable_responses = [str(x) for x in acceptable_responses]

    if quit_ok:
        acceptable_responses.extend(['q', 'Q'])

    if default_input and show_default:
        prompt_to_use = '%s [%s]: ' % (user_prompt, default_input)
    else:
        prompt_to_use = '%s: ' % user_prompt

    user_input = raw_input(prompt_to_use).strip()

    if not user_input and default_input in acceptable_responses:
        return default_input

    if user_input not in acceptable_responses:
        puts(colored.red('Sorry, %s is not a valid entry. Please try again.' % user_input))
        return choice_prompt(
                user_prompt=user_prompt,
                acceptable_responses=acceptable_responses,
                default_input=default_input,
                show_default=show_default,
                )

    return user_input


def get_user_entropy(user_prompt=DEFAULT_PROMPT):
    return getpass('%s: ' % user_prompt)


def get_crypto_qty(max_num, input_type, user_prompt=DEFAULT_PROMPT,
        default_input=None, show_default=False, quit_ok=False):

    assert input_type in UNIT_CHOICES, input_type

    if default_input and show_default:
        prompt_to_use = '%s [%s]: ' % (user_prompt, default_input)
    else:
        prompt_to_use = '%s: ' % user_prompt

    user_input = raw_input(prompt_to_use).strip()

    if default_input and not user_input:
        return int(default_input)

    if quit_ok and user_input in ['q', 'Q']:
        return user_input

    try:
        user_float = float(user_input.replace(',', ''))
    except ValueError:
        puts(colored.red('%s is not an integer. Please try again.' % user_input))
        return get_crypto_qty(
                max_num=max_num,
                default_input=default_input,
                show_default=show_default,
                )
    if user_float <= 0:
        puts(colored.red('%s <  0. Please try again.' % (
            format_output(user_float, output_type=input_type),
            )))
        return get_crypto_qty(
                max_num=max_num,
                default_input=default_input,
                show_default=show_default,
                )
    if max_num is not None and user_float > max_num:
        puts(colored.red('%s >  %s. Please try again.' % (
            format_output(user_float, output_type=input_type),
            format_output(max_num, output_type=input_type),
            )))
        return get_crypto_qty(
                max_num=max_num,
                input_type=input_type,
                default_input=default_input,
                show_default=show_default,
                )

    return user_float


def get_int(max_int, min_int=1, user_prompt=DEFAULT_PROMPT, default_input=None,
        show_default=False, quit_ok=False):
    if default_input and show_default:
        prompt_to_use = '%s [%s]: ' % (user_prompt, default_input)
    else:
        prompt_to_use = '%s: ' % user_prompt

    user_input = raw_input(prompt_to_use).strip()

    if default_input and not user_input:
        return int(default_input)

    if quit_ok and user_input in ['q', 'Q']:
        return user_input

    try:
        user_int = int(user_input.replace(',', ''))
    except ValueError:
        puts(colored.red('%s is not an integer. Please try again.' % user_input))
        return get_int(
                max_int=max_int,
                min_int=min_int,
                default_input=default_input,
                show_default=show_default,
                )
    if user_int < min_int:
        puts(colored.red('%s <  %s. Please try again.' % (
            user_int,
            min_int,
            )))
        return get_int(
                max_int=max_int,
                min_int=min_int,
                default_input=default_input,
                show_default=show_default,
                )
    if user_int > max_int:
        puts(colored.red('%s >  %s. Please try again.' % (
            user_int,
            max_int,
            )))
        return get_int(
                max_int=max_int,
                min_int=min_int,
                default_input=default_input,
                show_default=show_default,
                )
    return user_int


def get_crypto_address(coin_symbol, user_prompt=DEFAULT_PROMPT, quit_ok=False):

    display_shortname = COIN_SYMBOL_MAPPINGS[coin_symbol]['display_shortname']
    destination_address = raw_input('%s: ' % user_prompt).strip()

    if quit_ok and destination_address in ['q', 'Q']:
        return destination_address

    if is_valid_address_for_coinsymbol(destination_address,
            coin_symbol=coin_symbol):
        return destination_address
    else:
        puts('Invalid %s address, try again' % display_shortname)
        return get_crypto_address(
                coin_symbol=coin_symbol,
                user_prompt=user_prompt,
                )


def get_wif_obj(network, user_prompt=DEFAULT_PROMPT):

    wif = raw_input('%s: ' % user_prompt).strip()
    try:
        return PrivateKey.from_wif(wif, network=network)
    except Exception:
        puts(colored.red('Invalid WIF `%s`, Please Try Again' % wif))
        return get_wif_obj(network=network, user_prompt=user_prompt)


def coin_symbol_chooser(user_prompt=DEFAULT_PROMPT):
    ACTIVE_COIN_SYMBOL_LIST = [x for x in COIN_SYMBOL_LIST if x != 'uro']
    for cnt, coin_symbol_choice in enumerate(ACTIVE_COIN_SYMBOL_LIST):
        with indent(2):
            puts(colored.cyan('%s: %s' % (
                cnt+1,
                COIN_SYMBOL_MAPPINGS[coin_symbol_choice]['display_name'],
                )))
    if ACTIVE_COIN_SYMBOL_LIST[4] == 'bcy':
        default_input = 5
        show_default = True
    else:
        default_input = None
        show_default = False
    coin_symbol_int = get_int(
            min_int=1,
            user_prompt=user_prompt,
            max_int=len(ACTIVE_COIN_SYMBOL_LIST),
            default_input=default_input,
            show_default=show_default,
            )

    return ACTIVE_COIN_SYMBOL_LIST[coin_symbol_int-1]


def txn_preference_chooser(user_prompt=DEFAULT_PROMPT):
    puts('How quickly do you want this transaction to confirm? The higher the miner preference, the higher the transaction fee.')
    TXN_PREFERENCES = (
            ('high', '1-2 blocks to confirm'),
            ('medium', '3-6 blocks to confirm'),
            ('low', '7+ blocks to confirm'),
            #  ('zero', 'no fee, may not ever confirm (advanced users only)'),
            )
    for cnt, pref_desc in enumerate(TXN_PREFERENCES):
        pref, desc = pref_desc
        with indent(2):
            puts(colored.cyan('%s (%s priority): %s' % (cnt+1, pref, desc)))
    choice_int = choice_prompt(
            user_prompt=user_prompt,
            acceptable_responses=range(1, len(TXN_PREFERENCES)+1),
            default_input='1',  # high pref
            show_default=True,
            )
    return TXN_PREFERENCES[int(choice_int)-1][0]


def confirm(user_prompt=DEFAULT_PROMPT, default=None):
    if default is True:
        prompt_to_use = user_prompt + ' [Y/n]: '
    elif default is False:
        prompt_to_use = user_prompt + ' [y/N]: '
    elif default is None:
        prompt_to_use = user_prompt + ': '
    else:
        raise Exception('Bad Default Value: %s' % default)
    user_input = raw_input(prompt_to_use).strip()
    if not user_input:
        return default
    elif user_input.lower() == 'y':
        return True
    elif user_input.lower() == 'n':
        return False
    else:
        puts(colored.red('`%s` is not a valid entry. Please enter either Y or N.' % user_input))
        return confirm(user_prompt=user_prompt, default=default)


# TODO: move to blockcypher python library
def first4mprv_from_mpub(mpub):
    coin_symbol = coin_symbol_from_mkey(mkey=mpub)
    return COIN_SYMBOL_MAPPINGS[coin_symbol]['first4_mprv']


def print_bcwallet_basic_pub_opening(mpub):
    with indent(2):
        puts(colored.magenta('$ bcwallet --wallet=%s\n' % mpub))


def print_pubwallet_notice(mpub):
    puts("You've opened your wallet in PUBLIC key mode, so you CANNOT sign transactions.")
    puts("To sign transactions, open your wallet in private key mode like this:\n")
    priv_to_display = first4mprv_from_mpub(mpub=mpub) + '...'
    print_bcwallet_basic_priv_opening(priv_to_display=priv_to_display)


def print_bcwallet_basic_priv_opening(priv_to_display):
    with indent(4):
        puts(colored.magenta('$ bcwallet --wallet=%s\n' % priv_to_display))


BCWALLET_PRIVPIPE_EXPLANATION = "You can also pipe in your wallet (perhaps to hide it from your bash history and/or encrypt your master private key):\n"


def print_bcwallet_piped_priv_opening(priv_to_display):
    with indent(4):
        puts(colored.magenta('$ echo %s | bcwallet\n' % priv_to_display))
