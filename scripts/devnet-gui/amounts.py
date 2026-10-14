"""Display conversion only; frozen consensus/wallet amounts remain uint64 integers.

Binding MINING_CONSENSUS.md display unit and pinned cryptonote_config.h:
CRYPTONOTE_DISPLAY_DECIMAL_POINT=12, COIN=1000000000000.
"""
import re
DECIMALS=12
ATOMIC_PER_PC=10**DECIMALS
MAX_ATOMIC=2**64-1
def parse(text,unit='PC',positive=True):
    if not isinstance(text,str) or len(text)>64:raise ValueError('Enter a short exact decimal amount.')
    text=text.strip()
    if unit=='PC':
        if not re.fullmatch(r'(0|[1-9][0-9]{0,7})(\.[0-9]{1,12})?',text):
            raise ValueError('Use digits and a decimal point, with at most 12 decimal places. No commas, signs or exponents.')
        whole,_,fraction=text.partition('.');value=int(whole)*ATOMIC_PER_PC+int(fraction.ljust(DECIMALS,'0'))
    elif unit=='atomic':
        if not re.fullmatch(r'(0|[1-9][0-9]{0,19})',text):raise ValueError('Atomic units must be a whole number without signs or separators.')
        value=int(text)
    else:raise ValueError('Unsupported amount unit.')
    if value>MAX_ATOMIC or value<0 or positive and value==0:raise ValueError('Amount must be positive and within the uint64 atomic-unit limit.')
    return value
def format_pc(value):
    if type(value) is not int or not 0<=value<=MAX_ATOMIC:raise ValueError('Invalid atomic amount.')
    whole,fraction=divmod(value,ATOMIC_PER_PC)
    return str(whole)+('.'+f'{fraction:012d}'.rstrip('0') if fraction else '')
def display(value):return 'UNKNOWN / unavailable' if value is None else format_pc(value)+' PC'
