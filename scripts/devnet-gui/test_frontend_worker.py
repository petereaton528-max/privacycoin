"""TEST ONLY fresh-process launch/crash helper; secrets enter stdin only."""
import json, sys, time
from bridge import Bridge
from gui import App,safe_root
from test_gui import wait,rss

root=safe_root();root.withdraw();bridge=Bridge(sys.argv[2],int(sys.argv[3]));app=App(root,bridge);wait(root,app)
if sys.argv[1]=='launch':
    print(json.dumps(dict(windows_working_set_bytes=rss(),backend_rss_kib=app.last['rss_kib'])),flush=True);app.shutdown()
else:
    password=sys.stdin.readline().rstrip('\n');app.vars['name'].set('Crash');app.vars['password'].set(password);app.open();wait(root,app)
    assert not app.last_error and app.last['balance']['balance']==0
    print('READY',flush=True);root.mainloop()
