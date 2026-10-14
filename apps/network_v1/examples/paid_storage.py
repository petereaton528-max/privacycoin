"""Real PC paid encrypted storage example, no automatic invocation.

Operator supplies an isolated existing Client, Session and private store. The
example does not provision capabilities, open a wallet, mine or choose a network.
Integration test calls these operations only on newly created disposable data.
"""
from apps.network_v1.sdk import Client


def prepare(private_directory, client, private_files, order_key, plaintext):
    service = Client.payments(private_directory, client, private_files)
    request = service.request(order_key, len(plaintext))
    return service, request


def authorize_once(service, order_key, wallet_session, consent):
    # Must follow operator's fee/balance review in the trusted wallet UI.
    return service.authorize(order_key, wallet_session, consent)


def deliver_after_independent_observation(service, order_key, plaintext):
    status = service.observe(order_key)
    if not status['entitled']:
        raise ValueError('NOT_SETTLED_OR_NOT_ENTITLED')
    return service.deliver(order_key, plaintext)


def process_callbacks(service, order_key, callback):
    """Durable pull outbox; consumer MUST deduplicate event.id before side effects.

    Crash after callback before ack redelivers. No URL/SSRF or secret-bearing HTTP.
    """
    for event in service.events(order_key):
        callback(event)
        service.acknowledge(order_key, event['id'])


def export_recovery(service, order_key, private_destination, password):
    """Export before closing the app; keep backup/password independently safe.

    A successful export proves bundle creation, not remote retention or recovery.
    Restore with privacy-network client's restore_bundle through the same pinned
    authenticated transport; use an explicit new private plaintext destination.
    """
    return service.export_recovery(order_key, private_destination, password)
