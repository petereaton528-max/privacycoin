"""Unapproved deterministic offline creator vesting schedule.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
TOTAL=159627169409884823
LIQUID=TOTAL//10
LOCKED=TOTAL-LIQUID
INTERVAL=65700
RELEASES=16
DOMAIN='PrivacyCoin/UNAPPROVED-CREATOR-VESTING-DRAFT/v1'
def schedule():
    base,remainder=divmod(LOCKED,RELEASES)
    return [dict(index=0,height=0,atomic=LIQUID)]+[dict(index=i,height=i*INTERVAL,atomic=base+(i<=remainder)) for i in range(1,RELEASES+1)]
def unlocked(height):
    if type(height) is not int or height<0 or height>=2**64:raise ValueError('HEIGHT')
    return sum(x['atomic'] for x in schedule() if x['height']<=height)
