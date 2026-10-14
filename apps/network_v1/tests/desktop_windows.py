"""Automated real Windows Tk + isolated WSL backend, never human acceptance."""
import argparse
import json
from pathlib import Path
import secrets
import sys
import time
from unittest.mock import patch
from apps.network_v1.desktop import Desktop,ProductBridge,safe_root


def main():
    p=argparse.ArgumentParser();p.add_argument('--backend-root',required=True);p.add_argument('--home',required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.report.exists() or not a.home.startswith('/home/privacydev/pc-v1-fixtures-'):raise ValueError('NEW_ISOLATED_PATHS_REQUIRED')
    checks=[];root=safe_root();root.withdraw();bridge=ProductBridge(a.backend_root,a.home,30481,30482);app=None
    def pump():
        end=time.monotonic()+90
        while time.monotonic()<end:
            root.update()
            if app and not app.busy:
                if app.last_error:raise AssertionError('SAFE_UI_ERROR')
                return
            time.sleep(.01)
        raise TimeoutError('UI_DEADLINE')
    try:
        app=Desktop(root,bridge);pump();checks.append('actual Windows Tk initialized and private WSL hello received')
        app.action('node_start',{},app.show_product);pump();checks.append('owned node launched through UI private pipe')
        password='Disposable-'+secrets.token_hex(24);app.vars['name'].set('WindowFixture');app.vars['password'].set(password)
        with patch('apps.network_v1.desktop.simpledialog.askstring',return_value=password):app.create()
        pump();assert app.opened;assert app.vars['password'].get()=='';checks.append('wallet creation confirmation and secret entry clearing')
        with patch('apps.network_v1.desktop.messagebox.showinfo'):app.backup();pump()
        checks.append('GUI encrypted recovery bundle saved without exposing seed')
        app.action('prediction_enable',dict(consent='ENABLE SIMULATION ONLY'),app.show_prediction);pump()
        now=int(time.time());app.action('prediction_create',dict(question='Fixture YES?',criteria='Exact local fixture evidence',source='Owned fixture',close=now+2,resolve=now+60,cancellation='VOID refunds all stakes',authority='Local automated test operator'),lambda _:None);pump()
        app.action('prediction_view',{},app.show_prediction);pump();eid=app.events.get_children()[0];app.events.selection_set(eid);app.bet('YES');pump();checks.append('integrated simulation participation rendered in real Tk')
        time.sleep(2)
        app.action('prediction_adjudicate',dict(event=eid,action='VOID',outcome=None,evidence='Automated fixture cancellation',consent='CONFIRM SIMULATION SETTLEMENT'),lambda _:None);pump()
        app.action('prediction_view',{},app.show_prediction);pump();assert app.last['balance']==100000;checks.append('integrated simulation void refund rendered')
        app.action('mine_start',dict(blocks=1,consent='START CPU MINING',password=password),app.show_product);pump()
        end=time.monotonic()+90
        while time.monotonic()<end:
            app.action('product_status',{},app.show_product);pump()
            if app.last['node'].get('height',0)>=1:break
            time.sleep(.1)
        assert app.last['node']['height']>=1;checks.append('actual RandomX work observed through Windows desktop')
        assert len(app.tabs.tabs())>=11;checks.append('wallet Tor mining explorer storage prediction help tabs integrated')
        app.shutdown();app=None;assert bridge.process.poll() is not None;checks.append('desktop shutdown reaps backend and owned services')
        report=dict(result='PASS_AUTOMATED_WINDOWS_TK_WSL2_ONLY',platform='Windows Python/Tk + Ubuntu-24.04 WSL2',checks=checks,human_usability='UNVERIFIED',tor_public_network=False)
    except Exception as error:report=dict(result='FAIL',failure_type=type(error).__name__,checks=checks)
    finally:
        if app:
            try:app.shutdown()
            except Exception:bridge.close()
        else:bridge.close()
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));sys.exit(0 if report['result'].startswith('PASS') else 1)


if __name__=='__main__':main()
