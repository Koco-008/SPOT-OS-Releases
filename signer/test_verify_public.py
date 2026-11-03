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
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        public=self.key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint=hashlib.sha256(public).hexdigest()
        contents={'spot_os/VERSION':b'0.1.5\n','spot_os/trust/spot-os-release.pub':public}
        internal=dict(kind='os-installer',version='0.1.5',revision='signed-os-updates-1',app_version='unchanged',
            files={n:hashlib.sha256(v).hexdigest() for n,v in contents.items()})
        contents['spot_os/PACKAGE.json']=json.dumps(internal).encode()
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            for n,v in contents.items():archive.writestr(n,v)
        self.payload=stream.getvalue()
        self.data=dict(schema=1,kind='spot-os',repository=verifier.REPOSITORY,platform='raspios-debian13-aarch64',
            tag='os-v0.1.5',version='0.1.5',revision='signed-os-updates-1',sequence=105,
            asset='spot-os-0.1.5.zip',size=len(self.payload),sha256=hashlib.sha256(self.payload).hexdigest(),
            source_commit='a'*40,channel='prerelease',notes='Test only',requires_os_min='0.1.4',requires_os_max='0.1.4',
            requires_app_min='0.28.13',reader_protocol=1,engine=1,reboot=False)

    def assets(self):
        raw=(json.dumps(self.data)+'\n').encode()
        files={'spot-os-0.1.5.zip':self.payload,'os-update.json':raw,'os-update.json.sig':self.key.sign(raw)}
        files['SHA256SUMS.txt']=''.join(hashlib.sha256(v).hexdigest()+'  '+n+'\n' for n,v in files.items()).encode()
        return files

    def verify(self,files=None,fingerprint=None):
        return verifier.verify(files or self.assets(),'os-v0.1.5','a'*40,105,'0.1.4',fingerprint or self.fingerprint)

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
        files=self.assets();files['spot-os-0.1.5.zip']+=b'trailing change'
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
            ('requires_app_min','0.28.12'),('reboot',True),('channel','stable'),
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
