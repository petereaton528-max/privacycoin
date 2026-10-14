"""Dependency-free Python read SDK. No credentials or signing facilities."""
import json
import re
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.parse import urlsplit
from urllib.error import HTTPError,URLError

def unique(items):
    # Keep the read SDK independent of node/network-selection imports.
    value={}
    for key,item in items:
        if key in value:raise ValueError('DUPLICATE_JSON')
        value[key]=item
    return value


class APIError(ValueError):
    def __init__(self,code,status=None,retryable=False):
        self.code=code;self.status=status;self.retryable=retryable
        super().__init__(code)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError('API_REDIRECT_DENIED')


class Client:
    def __init__(self, base='http://127.0.0.1:29880', *, allow_clearnet=False):
        u = urlsplit(base)
        if u.username or u.password or u.query or u.fragment or u.path not in ('','/') or not (
            u.scheme == 'https' or u.scheme == 'http' and u.hostname in ('127.0.0.1','localhost')):
            raise ValueError('HTTPS_OR_LOOPBACK_REQUIRED')
        if u.hostname not in ('127.0.0.1','localhost') and not allow_clearnet:
            raise ValueError('LOCAL_API_DEFAULT_REMOTE_CLEARNET_REQUIRES_EXPLICIT_OPT_IN')
        self.base = base.rstrip('/')
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, path):
        if not isinstance(path,str) or not path.startswith('/api/v1/') or len(path)>1024 or any(x in path for x in ('\r','\n','#','\\')):raise APIError('API_PATH')
        try:
            with self.opener.open(Request(self.base + path, headers={'Accept':'application/json'}), timeout=6) as response:
                raw = response.read(1048577)
                if len(raw) > 1048576 or response.headers.get_content_type() != 'application/json':raise APIError('API_RESPONSE_BOUNDS')
                return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(APIError('API_JSON')))
        except (json.JSONDecodeError,UnicodeError):raise APIError('API_JSON') from None
        except HTTPError as error:
            status=error.code;error.close()
            raise APIError('API_HTTP_REJECTED',status,status in (429,503)) from None
        except (URLError,OSError,TimeoutError):raise APIError('API_UNAVAILABLE',retryable=True) from None

    @staticmethod
    def payments(private_directory,operator_client,private_files):
        """Scoped private SDK; never exposes spending authority to HTTP."""
        from .payments import Payments
        return Payments(private_directory,operator_client,private_files)

    def network(self):
        return self.get('/api/v1/network')

    def blocks(self, offset=0, limit=25):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('PAGE')
        return self.get(f'/api/v1/blocks?offset={offset}&limit={limit}')

    def block(self, block):
        if not isinstance(block,str) or not re.fullmatch('[0-9a-f]{64}', block):
            raise ValueError('HASH')
        return self.get('/api/v1/blocks/'+block)

    def leaderboard(self, day=None):
        if day is not None and (not isinstance(day,str) or not re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}', day)):
            raise ValueError('DAY')
        return self.get('/api/v1/leaderboard'+('' if day is None else '?day='+day))
