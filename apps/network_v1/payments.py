"""Trusted local application adapter, deliberately absent from the public server.

Client and wallet Session are operator-provisioned objects. Keep this process and
private store under a separate OS account/directory from the public web process.
No Internet signing, admin forwarding, autonomous payment or outbound callbacks.
"""
import hashlib
import re


class Payments:
    def __init__(self, directory, client, private_files):
        self.files = private_files
        self.client = client
        self.directory = directory
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.files.directory(directory):
            pass

    def path(self, key):
        if not isinstance(key, str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}', key):
            raise ValueError('IDEMPOTENCY_KEY')
        return self.directory/(key+'.payment-intent')

    def load(self, path):
        # Use the already audited duplicate-key rejecting wallet JSON decoder.
        return self.files.f.decode(self.files.read_private(path))

    def save(self, path, value, replace=False):
        self.files.write_private(path, self.files.f.canonical(value), replace=replace)

    def request(self, key, plain_bytes):
        if type(plain_bytes) is not int or not 1 <= plain_bytes <= 1048576:
            raise ValueError('SIZE')
        path = self.path(key)
        with self.files.lock(path):
            if path.exists():
                record = self.load(path)
                if record['bytes'] != plain_bytes:
                    raise ValueError('IDEMPOTENCY_CONFLICT')
                if record['phase'] == 'REQUEST_UNKNOWN':
                    raise ValueError('REQUEST_UNKNOWN_NO_AUTOMATIC_RETRY')
                return dict(quote=record['quote'], phase=record['phase'])
            # Persist reservation before external quote side effect. Failure is
            # fail-closed, not globally exactly-once after lost/stale backups.
            record = dict(version=1, bytes=plain_bytes, phase='REQUEST_UNKNOWN', events=[], acknowledged=[])
            self.save(path, record)
            quote = self.client.quote(plain_bytes)
            record.update(quote=quote['id'], phase='REQUESTED')
            self.save(path, record, True)
            return dict(quote=quote['id'], phase='REQUESTED')

    def authorize(self, key, session, consent):
        path = self.path(key)
        with self.files.lock(path):
            record = self.load(path)
            if consent != 'CONFIRM' or record['phase'] != 'REQUESTED':
                raise ValueError('CONSENT_OR_ATTEMPT_DENIED')
            record['phase'] = 'AUTHORIZED_UNKNOWN'
            self.save(path, record, True)
            self.client.pay(record['quote'], session, consent)
            record['phase'] = 'SUBMITTED_NOT_SETTLED'
            self.save(path, record, True)
            return dict(quote=record['quote'], phase=record['phase'])

    def observe(self, key):
        path = self.path(key)
        with self.files.lock(path):
            record = self.load(path)
            if 'quote' not in record:
                raise ValueError('REQUEST_UNKNOWN_MANUAL_ASSOCIATION_REQUIRED')
            result = self.client.status(record['quote'])
            # Provider is the independent observer; never accept a client tx ID
            # or arbitrary callback as evidence of payment/entitlement.
            state = result['state']
            allowed = {'CONFIRMED_LOCAL','MEMPOOL_ONLY','EXPIRED','UNKNOWN_RECONCILE',
                       'REVOKED_RECONCILE','QUOTED','UNPAID','UNKNOWN','PENDING'}
            if state not in allowed:
                state = 'UNKNOWN_RECONCILE'
            if not record['events'] or record['events'][-1]['state'] != state:
                if len(record['events']) >= 256:
                    raise ValueError('OUTBOX_FULL_MANUAL_REVIEW_REQUIRED')
                number = len(record['events'])
                event = dict(id=hashlib.sha256((key+'/'+str(number)+'/'+state).encode()).hexdigest(),
                             sequence=number, state=state)
                record['events'].append(event)
                self.save(path, record, True)
            return dict(quote=record['quote'], state=state,
                        entitled=state=='CONFIRMED_LOCAL', freshness='UNKNOWN')

    def events(self, key):
        path = self.path(key)
        with self.files.lock(path):
            record = self.load(path)
            return [e for e in record['events'] if e['id'] not in record['acknowledged']]

    def acknowledge(self, key, event_id):
        path = self.path(key)
        with self.files.lock(path):
            record = self.load(path)
            if event_id not in {e['id'] for e in record['events']}:
                raise ValueError('UNKNOWN_EVENT')
            if event_id not in record['acknowledged']:
                record['acknowledged'].append(event_id)
                self.save(path, record, True)

    def deliver(self, key, plain):
        path = self.path(key)
        with self.files.lock(path):
            record = self.load(path)
            qid = record['quote']
            if len(plain) != record['bytes']:
                raise ValueError('SIZE_CONFLICT')
            upload = self.client.home/(qid+'.upload')
            fingerprint = hashlib.sha256(plain).hexdigest()
            if 'plain_hash' in record and record['plain_hash'] != fingerprint:
                raise ValueError('PAYLOAD_CONFLICT')
            if 'plain_hash' not in record:
                record['plain_hash'] = fingerprint
                self.save(path, record, True)
            if not upload.exists():
                if record.get('cipher_reserved'):
                    raise ValueError('ORIGINAL_UPLOAD_MISSING_NO_REENCRYPTION')
                record['cipher_reserved'] = True
                self.save(path, record, True)
                self.client.encrypt(qid, plain)
            else:
                # A pre-existing intent upload must be the same original object.
                saved = self.client.home/(qid+'.upload')
                material = self.files.f.decode(self.files.read_private(saved))
                if material['bundle']['plain_hash'] != fingerprint:
                    raise ValueError('ORIGINAL_UPLOAD_REQUIRED')
            return self.client.upload(qid)

    def export_recovery(self, key, destination, password):
        """Private encrypted retrieval backup; no payment or entitlement grant.

        May be exported after original encryption even when Provider is offline.
        Uses the existing audited bundle encryption and no-clobber private writer.
        Destination and password stay in the trusted local process, never HTTP.
        """
        path = self.path(key)
        with self.files.lock(path):
            record = self.load(path)
            if not record.get('cipher_reserved') or 'plain_hash' not in record:
                raise ValueError('ORIGINAL_ENCRYPTED_UPLOAD_REQUIRED')
            qid = record['quote']
            material = self.files.f.decode(self.files.read_private(self.client.home/(qid+'.upload')))
            if material['bundle']['plain_hash'] != record['plain_hash']:
                raise ValueError('ORIGINAL_UPLOAD_REQUIRED')
            self.client.export(qid, destination, password)
            return dict(quote=qid, encrypted_recovery_exported=True,
                        scope='RETRIEVAL_AUTHORITY_NOT_PAYMENT_OR_AVAILABILITY_GUARANTEE')
