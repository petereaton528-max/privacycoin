'use strict';
const element = id => document.getElementById(id);
async function read(path) { const r = await fetch(path, {cache:'no-store'}); if (!r.ok) throw new Error('查询暂不可用'); return r.json(); }
async function rank(day) { try { element('rank').textContent=JSON.stringify(await read('/api/v1/leaderboard'+(day?'?day='+encodeURIComponent(day):'')),null,2); } catch(e) { element('error').textContent=e.message; } }
async function refresh() {
  try {
    const [network, blocks] = await Promise.all([read('/api/v1/network'),read('/api/v1/blocks?limit=25')]);
    element('network').textContent=JSON.stringify(network,null,2); element('blocks').replaceChildren();
    for (const b of blocks.blocks) { const row=document.createElement('tr'); for (const value of [b.height,b.hash,new Date(b.timestamp*1000).toISOString(),b.reward]) { const cell=document.createElement('td'); cell.textContent=String(value); row.appendChild(cell); } element('blocks').appendChild(row); }
    element('error').textContent='';
  } catch(e) { element('error').textContent=e.message; }
}
element('refresh').onclick=refresh; element('daily').onclick=()=>rank(element('day').value); element('total').onclick=()=>rank(); refresh(); rank();
