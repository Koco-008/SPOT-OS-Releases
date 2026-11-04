"""Public re-download verifier; ephemeral identities, no production secrets."""
import hashlib
import io
import json
from unittest import TestCase, mock
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
import verify_public as verifier


class PublicVerificationTests(TestCase):
    VERSION = '0.1.5'
    SEQUENCE = 105
    PREVIOUS = '0.1.4'
    CHANNEL = 'prerelease'

    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        public=self.key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint=hashlib.sha256(public).hexdigest()
        contents={'spot_os/VERSION':(self.VERSION+'\n').encode(),'spot_os/trust/spot-os-release.pub':public}
        internal=dict(schema=1,kind='os-installer',version=self.VERSION,revision='signed-os-updates-1',app_version='unchanged',
            files={n:hashlib.sha256(v).hexdigest() for n,v in contents.items()})
        contents['spot_os/PACKAGE.json']=json.dumps(internal).encode()
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            for n,v in contents.items():archive.writestr(n,v)
        self.payload=stream.getvalue()
        self.data=dict(schema=1,kind='spot-os',repository=verifier.REPOSITORY,platform='raspios-debian13-aarch64',
            tag='os-v'+self.VERSION,version=self.VERSION,revision='signed-os-updates-1',sequence=self.SEQUENCE,
            asset='spot-os-'+self.VERSION+'.zip',size=len(self.payload),sha256=hashlib.sha256(self.payload).hexdigest(),
            source_commit='a'*40,channel=self.CHANNEL,notes='Test only',requires_os_min=self.PREVIOUS,requires_os_max=self.PREVIOUS,
            requires_app_min='0.28.13',reader_protocol=1,engine=1,reboot=False)

    def assets(self):
        raw=(json.dumps(self.data)+'\n').encode()
        files={self.data['asset']:self.payload,'os-update.json':raw,'os-update.json.sig':self.key.sign(raw)}
        files['SHA256SUMS.txt']=''.join(hashlib.sha256(v).hexdigest()+'  '+n+'\n' for n,v in files.items()).encode()
        return files

    def verify(self,files=None,fingerprint=None):
        return verifier.verify(files or self.assets(),'os-v'+self.VERSION,'a'*40,self.SEQUENCE,self.PREVIOUS,fingerprint or self.fingerprint)

    def test_complete_release_chain(self):
        proof=self.verify()
        self.assertTrue(proof['signature_valid'] and proof['all_members_verified'])
        self.assertEqual(proof['requires_app_min'],'0.28.13')

    def test_foreign_identity_rejected(self):
        with self.assertRaisesRegex(ValueError,'fingerprint'):self.verify(fingerprint='0'*64)

    def test_signature_tampering_rejected(self):
        files=self.assets();files['os-update.json']+=b' '
        with self.assertRaises(InvalidSignature):self.verify(files)

    def test_zip_tampering_rejected(self):
        files=self.assets();files[self.data['asset']]+=b'trailing change'
        with self.assertRaisesRegex(ValueError,'ZIP'):self.verify(files)

    def test_checksums_rejected(self):
        files=self.assets();files['SHA256SUMS.txt']=b'wrong'
        with self.assertRaises(ValueError):self.verify(files)

    def test_each_inner_member_is_verified(self):
        contents=verifier.archive_members(self.payload)
        contents['spot_os/VERSION']=b'mutated member'
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            for n,v in contents.items():archive.writestr(n,v)
        self.payload=stream.getvalue()
        self.data.update(size=len(self.payload),sha256=hashlib.sha256(self.payload).hexdigest())
        with self.assertRaisesRegex(ValueError,'member'):self.verify()

    def test_compatibility_provenance_and_prerelease(self):
        for field,value in (('requires_os_min','0.1.3'),('requires_os_max','0.1.5'),
            ('requires_app_min','0.28.12'),('reboot',True),('channel','prerelease' if self.CHANNEL=='stable' else 'stable'),
            ('source_commit','b'*40),('sequence',104)):
            with self.subTest(field=field):
                old=self.data[field];self.data[field]=value
                with self.assertRaisesRegex(ValueError,'compatibility'):self.verify()
                self.data[field]=old

    def test_extra_asset_rejected(self):
        files=self.assets();files['extra']=b'extra'
        with self.assertRaisesRegex(ValueError,'four'):self.verify(files)

    def test_downloader_never_passes_auth_or_uses_proxy(self):
        response=mock.MagicMock();response.__enter__.return_value.read.return_value=b'test'
        opener=mock.Mock();opener.open.return_value=response
        with mock.patch.object(verifier.urllib.request,'build_opener',return_value=opener) as build:
            self.assertEqual(verifier.download('os-v0.1.5','os-update.json'),b'test')
        request=opener.open.call_args.args[0]
        self.assertEqual(request.headers,{'User-agent':'SPOT-OS-public-verifier'})
        self.assertEqual(build.call_args.args[0].proxies,{})


class Public016VerificationTests(PublicVerificationTests):
    VERSION = '0.1.6'
    SEQUENCE = 106

    def test_exact_016_contract_rejects_even_correctly_signed_wrong_metadata(self):
        for field, values in {
            'sequence': (self.SEQUENCE-1,self.SEQUENCE+1), 'requires_app_min': ('0.28.12', '0.28.14'),
            'requires_os_min': tuple(v for v in ('0.1.3','0.1.4','0.1.5','0.1.6','0.1.7') if v!=self.PREVIOUS),
            'requires_os_max': tuple(v for v in ('0.1.3','0.1.4','0.1.5','0.1.6','0.1.7') if v!=self.PREVIOUS),
            'channel': ('prerelease' if self.CHANNEL=='stable' else 'stable',), 'reboot': (True,), 'tag': ('os-v0.1.5',),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    old = self.data[field]
                    self.data[field] = value
                    with self.assertRaisesRegex(ValueError, 'compatibility'):
                        self.verify()
                    self.data[field] = old

    def test_signer_to_public_verifier_roundtrip(self):
        """Exercise actual signing with the existing ephemeral test identity only."""
        import tempfile
        from pathlib import Path
        from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
        import sign_candidate as signer
        contents = verifier.archive_members(self.payload)
        proof = dict(version=self.VERSION, asset=self.data['asset'], size=len(self.payload),
                     sha256=hashlib.sha256(self.payload).hexdigest())
        internal = json.loads(contents['spot_os/PACKAGE.json'])
        env = dict(SOURCE_COMMIT='a'*40, APPROVED_COMMIT='a'*40, SIGNING_ENABLED='true',
            SOURCE_ACTIONS_TOKEN='test-only', PUBLIC_KEY_SHA256=self.fingerprint,
            OS_SIGNING_KEY=self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(),
            RELEASE_TAG='os-v'+self.VERSION, RELEASE_SEQUENCE=str(self.SEQUENCE), PREVIOUS_OS=self.PREVIOUS, RELEASE_CHANNEL=self.CHANNEL,
            STABLE_RELEASES_ENABLED='true', HARDWARE_APPROVED='true')
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)/'out'
            with mock.patch.dict(signer.os.environ, env, clear=True), mock.patch.object(signer, 'Path', return_value=out), \
                    mock.patch.object(signer, 'get_candidate', return_value=(proof,self.payload,internal,contents['spot_os/trust/spot-os-release.pub'])):
                signer.main()
            self.assertTrue(self.verify({p.name:p.read_bytes() for p in out.iterdir()})['signature_valid'])

    def test_signer_rejects_unapproved_commit_or_stable_channel_before_candidate_access(self):
        import sign_candidate as signer
        env = dict(SOURCE_COMMIT='a'*40, APPROVED_COMMIT='a'*40, SIGNING_ENABLED='true',
            SOURCE_ACTIONS_TOKEN='test-only', OS_SIGNING_KEY='not-loaded', PUBLIC_KEY_SHA256='0'*64,
            RELEASE_TAG='os-v0.1.6', RELEASE_SEQUENCE='106', PREVIOUS_OS='0.1.4', RELEASE_CHANNEL='prerelease')
        for field,value in (('APPROVED_COMMIT','b'*40),('RELEASE_CHANNEL','stable')):
            with mock.patch.dict(signer.os.environ, dict(env, **{field:value}), clear=True), \
                    mock.patch.object(signer,'get_candidate') as candidate:
                with self.assertRaisesRegex(RuntimeError,'not approved'):
                    signer.main()
                candidate.assert_not_called()
