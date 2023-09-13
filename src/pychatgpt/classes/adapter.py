import ssl
from requests import adapters
from urllib3 import poolmanager

class ForceTLSV1Adapter(adapters.HTTPAdapter):
    """Require TLSv1 for the connection"""
    def init_poolmanager(self, connections, maxsize, block=False):
        # This method gets called when there's no proxy.
        self.poolmanager = poolmanager.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLSv1,
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        # This method is called when there is a proxy.
        proxy_kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1
        return super(ForceTLSV1Adapter, self).proxy_manager_for(proxy, **proxy_kwargs)