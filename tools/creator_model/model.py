"""Exact unapproved emission alternatives. All monetary arithmetic is integer.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,csv,hashlib,json
from pathlib import Path
UNIT=10**12
REFERENCE=2**64-1
TAIL=600_000_000_000
SHIFT=19
YEAR_BLOCKS=365*24*60//2
FOUR_YEAR_BLOCKS=4*YEAR_BLOCKS
def natural(value):
    if type(value) is not int or value<0 or value>=2**256:raise ValueError('UNSIGNED_256_INTEGER_REQUIRED')
    return value
def subsidy(counter):return max((REFERENCE-min(natural(counter),REFERENCE))>>SHIFT,TAIL)
def pc(amount):
    natural(amount);whole,fraction=divmod(amount,UNIT);return str(whole)+'.'+str(fraction).zfill(12)
def ratio(numerator,denominator,places=12):
    if denominator==0:return None
    # Display truncation only. Exact numerator/denominator retained alongside it.
    q=numerator*10**places//denominator
    return dict(numerator=str(numerator),denominator=str(denominator),decimal=str(q//10**places)+'.'+str(q%10**places).zfill(places),rounding='TRUNCATE_DISPLAY_ONLY')
def schedule(heights,initial_counter=0):
    initial_counter=natural(initial_counter);values=list(heights)
    if any(type(h) is not int for h in values):raise ValueError('INTEGER_HEIGHT_REQUIRED')
    targets=sorted(set(values))
    if not targets or targets[0]<0 or targets[-1]>60*YEAR_BLOCKS:raise ValueError('BOUNDED_HEIGHTS_REQUIRED')
    mined=0;height=0;tail_height=None;points={}
    for target in targets:
        while height<target:
            reward=subsidy(initial_counter+mined)
            if reward==TAIL:
                if tail_height is None:tail_height=height+1
                mined+=(target-height)*TAIL;height=target;break
            mined+=reward;height+=1
        points[target]=mined
    return dict(points=points,tail_first_height=tail_height,initial_counter=initial_counter,initial_reward=subsidy(initial_counter))
def report():
    heights={0,1,2,59,60,74,75,720,5040,FOUR_YEAR_BLOCKS+720}
    heights.update(y*YEAR_BLOCKS for y in range(52))
    base=schedule(heights);m=base['points'];m4=m[FOUR_YEAR_BLOCKS]
    allocations={'A_zero':0,'B_one_percent_mining':m4//100,'C_one_percent_total':m4//99}
    rows=[]
    for year in range(1,51):
        height=year*YEAR_BLOCKS;annual=m[height]-m[height-YEAR_BLOCKS];forward=m[height+YEAR_BLOCKS]-m[height]
        row=dict(year=year,height=height,mining_year_atomic=annual,mining_cumulative_atomic=m[height],mining_year_pc=pc(annual),mining_cumulative_pc=pc(m[height]),forward_annual_mining_atomic=forward,scenarios={})
        for name,allocation in allocations.items():
            total=m[height]+allocation
            row['scenarios'][name]=dict(creator_atomic=allocation,total_issued_atomic=total,total_issued_pc=pc(total),creator_percent_issued=ratio(100*allocation,total),supply_increase_percent_vs_zero=ratio(100*allocation,m[height]),forward_annual_inflation_percent=ratio(100*forward,total),backward_annual_inflation_percent=ratio(100*annual,m[height-YEAR_BLOCKS]+allocation))
        rows.append(row)
    early=[dict(height=h,mining_atomic=m[h],B_total_atomic=m[h]+allocations['B_one_percent_mining'],B_creator_percent_issued=ratio(100*allocations['B_one_percent_mining'],m[h]+allocations['B_one_percent_mining'])) for h in (0,1,60,720,5040)]
    coupled=schedule([1,2,YEAR_BLOCKS,2*YEAR_BLOCKS,FOUR_YEAR_BLOCKS,10*YEAR_BLOCKS],allocations['B_one_percent_mining'])
    return dict(status='UNAPPROVED_OFFLINE_MODEL',atomic_units_per_pc=UNIT,subsidy_formula='max((2**64-1-min(mining_issued,2**64-1)) >> 19, 600000000000)',block_window=FOUR_YEAR_BLOCKS,year_definition='Fixed 365-day target years: 262800 blocks; not actual elapsed calendar years',rounding='Allocation FLOOR to whole atomic units; exact ratios retained; no monetary floats',M4_atomic=m4,M4_pc=pc(m4),allocations={name:dict(atomic=a,pc=pc(a),share_of_M4_percent=ratio(100*a,m4),share_of_four_year_total_percent=ratio(100*a,m4+a)) for name,a in allocations.items()},calendar_1461_days=dict(target_blocks=FOUR_YEAR_BLOCKS+720,mining_atomic=m[FOUR_YEAR_BLOCKS+720],B_allocation_atomic=m[FOUR_YEAR_BLOCKS+720]//100),tail_first_height=base['tail_first_height'],tail_target_seconds=base['tail_first_height']*120,tail_target_years=ratio(base['tail_first_height'],YEAR_BLOCKS),annual_tail_atomic=YEAR_BLOCKS*TAIL,year_by_year=rows,early_concentration=early,counter_coupling_comparison=dict(scope='Same B allocation, but counted in the subsidy counter; not the recommended additive schedule',initial_reward_atomic=coupled['initial_reward'],mining_M4_atomic=coupled['points'][FOUR_YEAR_BLOCKS],mining_shortfall_M4_atomic=m4-coupled['points'][FOUR_YEAR_BLOCKS],allocation_percent_actual_M4=ratio(100*allocations['B_one_percent_mining'],coupled['points'][FOUR_YEAR_BLOCKS]),tail_first_height=coupled['tail_first_height']),circulating_supply='Unknown: issued includes immature outputs; lost keys, spending and market liquidity are not inferred',lifetime_share='No finite 1% lifetime allocation under indefinite tail; a fixed allocation share tends to zero')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--table',type=Path,required=True);a=p.parse_args()
    result=report()
    with a.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    with a.table.open('x',newline='') as stream:
        fields=['year','height','mining_year_pc','mining_cumulative_pc','zero_total_pc','B_total_pc','C_total_pc','B_creator_percent','B_forward_inflation_percent']
        writer=csv.DictWriter(stream,fieldnames=fields,lineterminator='\n');writer.writeheader()
        for row in result['year_by_year']:
            b=row['scenarios']['B_one_percent_mining'];c=row['scenarios']['C_one_percent_total']
            writer.writerow(dict(year=row['year'],height=row['height'],mining_year_pc=row['mining_year_pc'],mining_cumulative_pc=row['mining_cumulative_pc'],zero_total_pc=row['mining_cumulative_pc'],B_total_pc=b['total_issued_pc'],C_total_pc=c['total_issued_pc'],B_creator_percent=b['creator_percent_issued']['decimal'],B_forward_inflation_percent=b['forward_annual_inflation_percent']['decimal']))
    print(json.dumps(dict(M4_atomic=result['M4_atomic'],allocations=result['allocations'],output=str(a.output))))
