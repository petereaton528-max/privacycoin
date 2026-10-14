"""Exercise actual independent nodes, RandomX, LMDB, sync and reorg.

No consensus arithmetic is implemented here. Expected first rewards and genesis
are immutable vectors; all block generation/validation takes place in C++.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/phase1'))
from client import call, exact, NETWORK, GENESIS, RPC_MAGIC
from build import ENV, archive, EVIDENCE, BUILD, SUFFIX

OUT = EVIDENCE
EXE = BUILD / ('phase1/privacycoin-devnet'+SUFFIX)
DATA = ROOT / 'devnet-data' / ('integration-' + uuid.uuid4().hex)
OUT.mkdir(parents=True, exist_ok=True)
archive(['integration','verified-blocks','A','B','C','D'])
DATA.mkdir(parents=True)
events = []
nodes = []
verified_blocks = {}

def check(ok, name, **details):
    events.append(dict(test=name, result='PASS' if ok else 'FAIL', **details))
    print(events[-1], flush=True)
    if not ok:
        raise AssertionError(name)

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class Node:
    def __init__(self, name, *, path=None, peer=None, defaults=False):
        self.name = name
        self.path = path or DATA / name
        self.p2p, self.rpc = (48080,48081) if defaults else (free_port(),free_port())
        self.log = (OUT / (name + '.log')).open('w', encoding='utf-8')
        args = [str(EXE), '--data-dir', str(self.path)]
        if not defaults:
            args += ['--p2p-port', str(self.p2p), '--rpc-port', str(self.rpc)]
        if peer:
            args += ['--peer-port', str(peer)]
        started = time.perf_counter()
        self.process = subprocess.Popen(args, cwd=ROOT, env=ENV, stdout=self.log, stderr=subprocess.STDOUT)
        nodes.append(self)
        self.commands = args
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f'{name} exited {self.process.returncode}: ' + (OUT / (name + '.log')).read_text())
            try:
                self.status()
                self.startup_seconds = time.perf_counter() - started
                return
            except (OSError, ConnectionError):
                time.sleep(.05)
        raise TimeoutError(name + ' startup')

    def request(self, command, **params):
        d = call(self.rpc, command, **params)
        if 'error' in d:
            raise RuntimeError(d['error'])
        return d

    def status(self):
        return self.request('status')

    def stop(self, crash=False):
        if self.process.poll() is None:
            if crash:
                self.process.kill()
            else:
                self.request('shutdown')
            self.process.wait(timeout=30)
        self.log.close()
        if not crash:
            check(self.process.returncode == 0, self.name + ' clean shutdown', exit_code=self.process.returncode)

    def mine(self, count, **params):
        before = self.status()
        cpu0 = process_metrics(self.process.pid)
        started = time.perf_counter()
        command = [sys.executable, str(ROOT/'scripts/phase1/client.py'), '--port', str(self.rpc),
            'start_mining', '--count', str(count)]
        if 'reward_key' in params:
            command += ['--reward-key', params['reward_key']]
        client = subprocess.run(command, cwd=ROOT, env=ENV, capture_output=True, timeout=15)
        check(client.returncode == 0 and json.loads(client.stdout).get('started') == 1,
            self.name + ' real CLI mining request', command=command, stderr=client.stderr.decode(errors='replace'))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            status = self.status()
            if status['mining_error']:
                raise RuntimeError(status['mining_error'])
            if status['mined'] >= before['mined'] + count and not status['mining']:
                elapsed = time.perf_counter() - started
                cpu1 = process_metrics(self.process.pid)
                return dict(seconds=elapsed, average_block_seconds=elapsed/count,
                    hashes_per_second=(status['mining_hashes']-before['mining_hashes'])/elapsed,
                    cpu_percent_one_core=100*(cpu1['cpu_seconds']-cpu0['cpu_seconds'])/elapsed,
                    status=status)
            time.sleep(.03)
        raise TimeoutError('mining')

def process_metrics(pid):
    if os.name != 'nt':
        stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return dict(cpu_seconds=(int(stat[11])+int(stat[12]))/os.sysconf('SC_CLK_TCK'),
                    working_set_bytes=int(stat[21])*os.sysconf('SC_PAGE_SIZE'),
                    source='/proc/PID/stat', rss_pages=int(stat[21]))
    from ctypes import wintypes as w
    class Counters(ctypes.Structure):
        _fields_ = [('cb', w.DWORD), ('PageFaultCount', w.DWORD)] + [(n, ctypes.c_size_t) for n in
            ['PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage',
             'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage']]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)]*4
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, ctypes.POINTER(Counters), w.DWORD]
    handle = kernel.OpenProcess(0x1000 | 0x10, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ts = [w.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(x) for x in ts]):
            raise ctypes.WinError(ctypes.get_last_error())
        c = Counters(); c.cb = ctypes.sizeof(c)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(c), c.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        ticks = sum((t.dwHighDateTime << 32) | t.dwLowDateTime for t in ts[2:])
        return dict(cpu_seconds=ticks/10000000, working_set_bytes=c.WorkingSetSize)
    finally:
        kernel.CloseHandle(handle)

def wait_tip(node, target, timeout=90):
    started = time.perf_counter()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = node.status()
        if s['tip'] == target['tip']:
            check((s['height'], s['work'], s['issued']) == (target['height'], target['work'], target['issued']),
                  node.name + ' matching height/work/issuance', status=s)
            return time.perf_counter() - started
        time.sleep(.05)
    raise TimeoutError('sync: ' + str(node.status()) + ' target ' + str(target))

def equal_blocks(a, b):
    ia = a.request('inventory')['blocks']; ib = b.request('inventory')['blocks']
    check(set(ia) == set(ib), 'identical synchronized block inventory', count=len(ia))
    for h in ia:
        contents = a.request('get_block', hash=h)
        check(contents == b.request('get_block', hash=h), 'identical block contents ' + h)
        verified_blocks[h] = contents

def reject(node, name, expected=None, **params):
    before = node.status()
    result = call(node.rpc, 'submit', **params)
    check('error' in result and (expected is None or expected in result['error']), name, error=result.get('error'))
    after = node.status()
    check(all(before[k] == after[k] for k in ['height', 'tip', 'work', 'issued']),
          name + ' leaves chain unchanged')

def read_varint(blob, offset):
    value, shift = 0, 0
    while True:
        byte = blob[offset]; offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
        shift += 7

def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128); value >>= 7
    out.append(value)
    return out

def header_offsets(blob):
    _, offset = read_varint(blob, 0)
    _, offset = read_varint(blob, offset)
    timestamp_start = offset
    _, timestamp_end = read_varint(blob, offset)
    return timestamp_start, timestamp_end, timestamp_end + 32

try:
    a = Node('A', defaults=True)
    check(a.status()['tip'] == GENESIS and a.status()['height'] == 0, 'real node enforces frozen genesis')
    genesis = a.request('get_block', hash=GENESIS)
    fixture = json.loads((ROOT / 'tests/phase0/genesis.json').read_text())
    check(genesis['block'] == fixture['serialized_hex'], 'node genesis equals frozen serialized vector')
    conflict = subprocess.run([str(EXE), '--data-dir', str(a.path), '--p2p-port', str(free_port()),
        '--rpc-port', str(free_port())], cwd=ROOT, env=ENV, capture_output=True, timeout=15)
    check(conflict.returncode != 0 and b'already in use' in conflict.stderr,
        'concurrent same-data-directory node refused', exit_code=conflict.returncode,
        stderr=conflict.stderr.decode(errors='replace'))
    idle = process_metrics(a.process.pid)
    first = a.request('template')
    check(first['difficulty'] == '1' and first['reward'] == 35184372088831, 'real initial mining template/reward')
    reject(a, 'claimed invalid difficulty rejected', block=first['block'], difficulty='2')
    reject(a, 'malformed block rejected', block='ffff')
    reject(a, 'noncanonical/trailing block rejected', block=first['block']+'00')
    raw = bytearray.fromhex(first['block'])
    timestamp_start, timestamp_end, nonce_offset = header_offsets(raw)
    future = raw[:timestamp_start] + varint(int(time.time())+7260) + raw[timestamp_end:]
    reject(a, 'invalid future timestamp rejected', expected='timestamp too far in future', block=future.hex())
    offset = nonce_offset + 4
    for _ in range(3):  # tx version, unlock height, generation input count
        _, offset = read_varint(raw, offset)
    check(raw[offset] == 255, 'template canonical generation input tag')
    offset += 1
    _, offset = read_varint(raw, offset)  # generation height
    outputs, offset = read_varint(raw, offset)
    amount_start = offset
    amount, amount_end = read_varint(raw, offset)
    check(outputs == 1 and amount == first['reward'], 'template serialized reward equals RPC reward')
    excessive = raw[:amount_start] + varint(amount+1) + raw[amount_end:]
    reject(a, 'excessive coinbase rejected', expected='coinbase subsidy/fee accounting', block=excessive.hex())
    header = bytearray.fromhex(first['block'])
    offset = 0
    for _ in range(3):  # Skip canonical major/minor/timestamp varints, not consensus arithmetic.
        while header[offset] & 128:
            offset += 1
        offset += 1
    header[offset:offset+32] = bytes(32)
    reject(a, 'wrong previous hash rejected', block=header.hex())
    bad = call(a.rpc, 'status', genesis='00'*32)
    check('error' in bad and 'incompatible' in bad['error'], 'wrong genesis handshake refused', error=bad.get('error'))
    with socket.create_connection(('127.0.0.1', a.p2p), timeout=10) as s:
        # Only send the header: server rejects the magic before reading a body.
        # Avoid unread body bytes causing an OS-level reset on socket close.
        s.sendall(b'MoneroMainnet!!!' + struct.pack('>I', 0))
        # Exactly 16 wrong bytes plus length, independent of a Monero implementation.
        response = exact(s, 20)
        size = struct.unpack('>I', response[16:])[0]
        error = json.loads(exact(s, size))
        check('magic' in error.get('error', ''), 'incompatible P2P magic rejected', error=error)
    for name, magic in [('Monero mainnet','1230f171610441611731008216a1a110'),
                        ('Monero testnet','1230f171610441611731008216a1a111'),
                        ('Monero stagenet','1230f171610441611731008216a1a112')]:
        with socket.create_connection(('127.0.0.1', a.p2p), timeout=10) as s:
            s.sendall(bytes.fromhex(magic)+struct.pack('>I',0))
            header=exact(s,20)
            response=json.loads(exact(s,struct.unpack('>I',header[16:])[0]))
            check('magic' in response.get('error',''), name+' pinned UUID rejected', error=response.get('error'))
    pow_node = Node('E-retarget')
    bootstrap = pow_node.request('template')
    pow_node.request('submit', block=bootstrap['block'], difficulty='1')
    second = pow_node.request('template', timestamp=bootstrap['timestamp'])
    pow_node.request('submit', block=second['block'], difficulty='1')
    retarget = pow_node.request('template', timestamp=bootstrap['timestamp'])
    check(retarget['difficulty'] == '120', 'real live DAA retarget for invalid PoW gate')
    candidate = bytearray.fromhex(retarget['block'])
    nonce_offset = header_offsets(candidate)[2]
    for nonce in range(256):
        candidate[nonce_offset:nonce_offset+4] = struct.pack('<I', nonce)
        before = pow_node.status()
        response = call(pow_node.rpc, 'submit', block=candidate.hex(), difficulty='120')
        if 'error' in response:
            check('invalid RandomX PoW' in response['error'], 'invalid real RandomX PoW rejected',
                  error=response['error'], nonce=nonce, template=retarget)
            check(all(pow_node.status()[k] == before[k] for k in ['height','tip','work','issued']),
                  'invalid PoW leaves chain unchanged')
            break
    else:
        raise AssertionError('No invalid PoW found in 256 real submissions')
    pow_node.stop()
    measurement = a.mine(6)
    after_mining_idle = process_metrics(a.process.pid)
    target = a.status()
    check(target['height'] == 6 and target['work'] == '6', 'real RandomX accepted six CPU-mined blocks', measurement=measurement)
    reject(a, 'duplicate block rejected', block=a.request('get_block', hash=target['tip'])['block'])
    check(a.request('get_block', hash=target['tip'])['reward'] > 0, 'accepted coinbase output reward')
    a.request('start_mining')
    a.request('stop_mining')
    check(a.status()['mining'] == 0, 'CPU miner stops cleanly')
    target = a.status()
    a.stop()
    a2 = Node('A-restart', path=a.path)
    check(all(a2.status()[k] == target[k] for k in ['height','tip','work','issued']),
          'clean restart preserves exact tip/work', before=target, after=a2.status())
    a2.mine(1); crash_tip = a2.status(); a2.stop(crash=True)
    a3 = Node('A-crash-restart', path=a.path)
    check(all(a3.status()[k] == crash_tip[k] for k in ['height','tip','work','issued']) and
          (os.name == 'nt' or a2.process.returncode == -9),
          'forced termination preserves committed LMDB chain', before=crash_tip,
          after=a3.status(), termination_exit_code=a2.process.returncode,
          termination='SIGKILL' if os.name != 'nt' else 'TerminateProcess')
    b = Node('B', peer=a3.p2p)
    sync_seconds = wait_tip(b, a3.status()); equal_blocks(a3, b)
    # Separate nodes from genesis; distinct public destinations create real branches.
    c = Node('C-isolated'); d = Node('D-isolated')
    c.mine(3)
    # The negative basepoint is a valid subgroup point, public and fixture-only.
    other_key = '58666666666666666666666666666666666666666666666666666666666666e6'
    d.mine(5, reward_key=other_key)
    left, right = c.status(), d.status()
    check(left['tip'] != right['tip'] and int(right['work']) > int(left['work']), 'isolated competing branches 3 versus 5 work', left=left, right=right)
    c.stop(); d.stop()
    d2 = Node('D-reconnect', path=d.path)
    c2 = Node('C-reconnect', path=c.path, peer=d2.p2p)
    reorg_seconds = wait_tip(c2, right)
    check(c2.status()['reorganizations'] >= 1 and c2.status()['disconnected'] >= 3, 'reorg disconnects losing three-block branch', status=c2.status())
    losing = c2.request('get_block', hash=left['tip'])
    check(losing['height'] == 3, 'disconnected block retained as valid inactive branch')
    # Restart D with reciprocal connection so both retain the entire block tree.
    d2.stop(); d3 = Node('D-bidirectional', path=d.path, peer=c2.p2p)
    wait_tip(d3, right)
    deadline = time.monotonic() + 30
    while set(d3.request('inventory')['blocks']) != set(c2.request('inventory')['blocks']) and time.monotonic() < deadline:
        time.sleep(.05)
    equal_blocks(c2, d3)
    measurements = dict(environment=platform.platform(), logical_cpus=os.cpu_count(),
        startup_seconds=a.startup_seconds, idle_before_cache_initialization=idle,
        idle_after_mining=after_mining_idle, mining=measurement,
        small_chain_sync_after_ready_seconds=sync_seconds,
        small_chain_start_and_sync_seconds=b.startup_seconds+sync_seconds,
        fork_sync_after_ready_seconds=reorg_seconds,
        last_mined_block_validation_ms=measurement['status']['validation_ms'], mode='RandomX standard-parameter light JIT, one mining thread',
        caveat='Short local engineering observation; CPU percent is relative to one logical core; hashes/sec count mining nonce hashes, excluding validation; initial cache setup included in elapsed time.')
    result = dict(result='PASS', events=events, measurements=measurements,
        executable_sha256=hashlib.sha256(EXE.read_bytes()).hexdigest(), data_directory=str(DATA),
        commands=[n.commands for n in nodes], date=time.strftime('%Y-%m-%dT%H:%M:%S%z'))
except BaseException as error:
    result = dict(result='FAIL', error=repr(error), events=events)
    raise
finally:
    for n in nodes:
        if n.process.poll() is None:
            try:
                n.request('shutdown'); n.process.wait(timeout=15)
            except BaseException:
                n.process.kill(); n.process.wait()
        n.log.close()
    (OUT / 'integration-results.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    (OUT / 'verified-blocks.json').write_text(json.dumps(verified_blocks, indent=2)+'\n', encoding='utf-8')
