"""Actual Tk/engine first-use, empty private data; automated, not human acceptance."""
import argparse
import json
from pathlib import Path
import secrets
import time
import traceback
from unittest.mock import patch
from apps.network_v1.desktop import Desktop,ProductBridge,safe_root
from apps.network_v1.onboarding import Guide


def main():
    p=argparse.ArgumentParser();p.add_argument('--backend-root');p.add_argument('--home',required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--port',type=int,default=32481);p.add_argument('--p2p',type=int,default=32482);p.add_argument('--local-payment-fixture',action='store_true');a=p.parse_args()
    if a.report.exists() or not a.home.startswith(('/home/privacydev/pc-v1-fixtures-rc4-','/home/privacydev/pc-v1-fixtures-rc5-')):raise ValueError('NEW_PRIVATE_FIXTURE_AND_REPORT_REQUIRED')
    start=time.monotonic();checks=[];measurements={};root=safe_root();root.withdraw();bridge=None;app=None;guide=None
    # Unexpected UI errors must fail the test, not wait on an unattended modal.
    alerts=patch('tkinter.messagebox.showerror',return_value=None);alerts.start()
    def pump():
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            root.update()
            if app and not app.busy:
                if app.last_error:raise AssertionError('safe UI operation failed')
                return
            time.sleep(.01)
        raise TimeoutError('first use UI deadline')
    try:
        bridge=ProductBridge(a.backend_root,a.home,a.port,a.p2p);app=Desktop(root,bridge);pump()
        measurements['interface_backend_ready_seconds']=round(time.monotonic()-start,3)
        checks.append('empty first-use private backend ready; no node/mining/network started')
        guide=Guide(app);guide.window.withdraw();password='Isolated-'+secrets.token_hex(24)
        guide.name.set('Beginner');guide.password.set(password);guide.repeat.set('incorrect');guide.unlock('create')
        assert not app.busy and not app.opened;checks.append('password mismatch rejected before wallet creation')
        guide.repeat.set(password);began=time.monotonic();guide.unlock('create');pump()
        assert app.opened and guide.password.get()==guide.repeat.get()==''
        measurements['create_wallet_and_owned_node_seconds']=round(time.monotonic()-began,3)
        assert not guide.verified and 'disabled' in guide.next_button.state();checks.append('real wallet create + automatic owned node + recovery prerequisite')
        with patch('tkinter.simpledialog.askstring',return_value='Beginner-recovery'):guide.backup()
        pump();assert guide.verified and 'disabled' in guide.next_button.state();checks.append('encrypted backup actual isolated save/load verification; acknowledgement still required')
        guide.ack.set(True);guide.acknowledge();assert 'disabled' not in guide.next_button.state();guide.network()
        pump();assert 'external synchronization' in guide.message.get();checks.append('network step discloses missing bootstrap rather than false synchronization')
        guide.close();guide=None
        app.action('product_status',{},app.show_product);pump();assert app.product_state['mining']['state']=='DISABLED' and app.product_state['tor']['state']=='DISABLED'
        measurements['backend_idle_rss_kib']=bridge.call('hello')['rss_kib'];checks.append('mining and Tor remain disabled after onboarding')
        app.vars['restore_source'].set('Beginner-recovery');app.vars['restore_name'].set('Recovered');app.vars['restore_password'].set(password);app.restore_ack.set(True)
        address=app.address.get();app.restore();pump();assert app.opened and app.address.get()==address;checks.append('real GUI recovery to new alias preserves receiving identity')
        assert all('prediction' not in app.tabs.tab(t,'text').lower() for t in app.tabs.tabs());checks.append('prediction absent from core navigation')
        portable=a.home+'/portable.pc-recovery'
        with patch.object(app,'recovery_file',return_value=portable):app.export_recovery()
        pump();assert 'decoded successfully' in app.recovery_output.get('1.0','end');checks.append('GUI portable encrypted export actually validated')
        with patch.object(app,'recovery_file',return_value=portable),patch('tkinter.simpledialog.askstring',side_effect=['Portable',password]),patch('tkinter.messagebox.askokcancel',return_value=True):app.import_recovery()
        pump();assert app.opened and app.address.get()==address and app.vars['name'].get()=='Portable';checks.append('GUI portable import preserves real receiving identity')
        if a.local_payment_fixture:
            from .gui_payments import exercise
            checks.extend(exercise(app,pump,a.home,a.port,a.p2p))
        mining_begin=bridge.call('product_status')['node']['height']
        app.action('mine_start',dict(blocks=1,consent='START CPU MINING',password=password,cpu_preset='light'),app.show_product);pump()
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            app.action('product_status',{},app.show_product);pump()
            if app.product_state['node'].get('height',0)>mining_begin:break
            time.sleep(.2)
        assert app.product_state['node']['height']>mining_begin;checks.append('explicit light-preset actual RandomX block accepted')
        page=bridge.call('history_page',offset=0);app.observed(page)
        assert len(page['history'])<=100 and page['history_page']['total']>=1 and 'disabled' in app.history_older.state()
        checks.append('real wallet output history is bounded and keyboard-accessible pager reflects available pages')
        began=time.monotonic();app.action('mine_stop',{},app.show_product);pump();assert app.product_state['mining']['state']=='STOPPED';measurements['mining_stop_seconds']=round(time.monotonic()-began,3)
        app.action('node_stop',{},app.show_product);pump();assert app.product_state['node']['state']=='STOPPED'
        app.action('node_start',{},app.show_product);pump();deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            app.action('product_status',{},app.show_product);pump()
            if app.product_state.get('node',{}).get('height',0)>=1:break
            time.sleep(.1)
        assert app.product_state['node']['height']>=1 and app.address.get()==address;checks.append('immediate owned node restart revalidates retained chain and wallet identity')
        began=time.monotonic();app.shutdown();app=None;assert bridge.process.poll() is not None
        measurements['owned_shutdown_seconds']=round(time.monotonic()-began,3);checks.append('stop mining and owned desktop shutdown')
        report=dict(result='PASS_AUTOMATED_REAL_FIRST_USE_NOT_BEGINNER_ACCEPTANCE',checks=checks,measurements=measurements,
                    native_windows_backend=False,clean_os=False,public_tor=False,human_acceptance='UNVERIFIED',network_first_peer_seconds='UNVERIFIED_NO_PUBLIC_BOOTSTRAP',global_sync='UNVERIFIED')
    except Exception as error:report=dict(result='FAIL',failure_type=type(error).__name__,failure_location=[dict(function=x.name,line=x.lineno) for x in traceback.extract_tb(error.__traceback__)],safe_ui_status=app.last_error if app else None,checks=checks,measurements=measurements)
    finally:
        alerts.stop()
        if app:
            try:app.shutdown()
            except Exception:
                if bridge:bridge.close()
        elif bridge:bridge.close()
    with a.report.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)


if __name__=='__main__':main()
