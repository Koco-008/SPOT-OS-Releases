"""Verify the actual public OS release without any token or private source code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request
from urllib.parse import urlsplit

from sign_candidate import archive_members, release_target_valid, RELEASES, MAX

REPOSITORY = 'Koco-008/SPOT-OS-Releases'
FIELDS = {'schema','kind','repository','platform','tag','version','revision','sequence',
          'asset','size','sha256','source_commit','channel','notes','requires_os_min',
          'requires_os_max','requires_app_min','reader_protocol','engine','reboot'}


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate JSON field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))


def download(tag, name):
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, url):
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.hostname not in
                    ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')
                    or parsed.username or parsed.password or parsed.port not in (None,443)):
                raise ValueError('Unexpected public release redirect')
            return urllib.request.Request(url, headers={'User-Agent':'SPOT-OS-public-verifier'})
    request = urllib.request.Request('https://github.com/'+REPOSITORY+'/releases/download/'+tag+'/'+name,
        headers={'User-Agent':'SPOT-OS-public-verifier'})
    # No credential helper, environment token, cookie jar or authenticated proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    with opener.open(request, timeout=60) as response:
        raw = response.read(MAX+1 if name.endswith('.zip') else 65537)
    if len(raw) > (MAX if name.endswith('.zip') else 65536):
        raise ValueError('Oversized public release asset')
    return raw


def verify(files, tag, commit, sequence, previous, fingerprint):
    if not re.fullmatch(r'os-v0\.[0-9]+\.[0-9]+', tag) or not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Exact release tag and source commit required')
    version = tag[4:]
    asset = 'spot-os-'+version+'.zip'
    if set(files) != {asset,'os-update.json','os-update.json.sig','SHA256SUMS.txt'}:
        raise ValueError('Exactly four OS assets required')
    payloads = archive_members(files[asset])
    public = payloads.get('spot_os/trust/spot-os-release.pub', b'')
    if not re.fullmatch('[a-f0-9]{64}', fingerprint) or hashlib.sha256(public).hexdigest() != fingerprint:
        raise ValueError('Independent OS key fingerprint differs')
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key = load_pem_public_key(public)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('OS Ed25519 key required')
    key.verify(files['os-update.json.sig'], files['os-update.json'])
    data = parse(files['os-update.json'])
    if (set(data) != FIELDS or data['schema'] != 1 or type(data['schema']) is not int or data['kind'] != 'spot-os'
        or data['repository'] != REPOSITORY or data['platform'] != 'raspios-debian13-aarch64'
        or data['tag'] != tag or data['version'] != version or data['source_commit'] != commit
        or data['asset'] != asset or data['sequence'] != sequence or type(data['sequence']) is not int
        or not release_target_valid(version, sequence, previous, tag)
        or data['requires_os_min'] != previous or data['requires_os_max'] != previous
        or data['requires_app_min'] != RELEASES[version][2]
        or data['channel'] != 'prerelease' or data['reboot'] is not False
        or data['reader_protocol'] != 1 or type(data['reader_protocol']) is not int
        or data['engine'] != 1 or type(data['engine']) is not int or type(data['size']) is not int):
        raise ValueError('Published OS compatibility/provenance differs')
    if len(files[asset]) != data['size'] or hashlib.sha256(files[asset]).hexdigest() != data['sha256']:
        raise ValueError('Published ZIP differs from signed manifest')
    checks = files['SHA256SUMS.txt'].decode('ascii').splitlines()
    expected = {name:hashlib.sha256(files[name]).hexdigest() for name in (asset,'os-update.json','os-update.json.sig')}
    actual = {}
    for line in checks:
        digest, name = line.split()
        if name in actual:
            raise ValueError('Duplicate checksum entry')
        actual[name] = digest
    if actual != expected:
        raise ValueError('Published checksums differ')
    internal = parse(payloads.get('spot_os/PACKAGE.json', b'{}'))
    if (internal.get('kind') != 'os-installer' or internal.get('version') != version
        or internal.get('revision') != data['revision'] or internal.get('app_version') != 'unchanged'
        or set(internal.get('files',{})) != set(payloads)-{'spot_os/PACKAGE.json'}
        or any(not n.startswith('spot_os/') for n in payloads)):
        raise ValueError('Published internal package differs')
    for name, digest in internal['files'].items():
        if hashlib.sha256(payloads[name]).hexdigest() != digest:
            raise ValueError('Published member differs')
    if payloads.get('spot_os/VERSION', b'').decode().strip() != version:
        raise ValueError('Published version file differs')
    return dict(tag=tag,source_commit=commit,zip_sha256=data['sha256'],signature_valid=True,
        key_sha256=fingerprint,all_members_verified=True,files=len(payloads),
        compatible_from_os=previous,requires_app_min=data['requires_app_min'],prerelease=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag',required=True);parser.add_argument('--commit',required=True)
    parser.add_argument('--sequence',type=int,required=True);parser.add_argument('--previous',required=True)
    parser.add_argument('--fingerprint',required=True);parser.add_argument('--output',type=Path,default=Path('public-verification.json'))
    args=parser.parse_args()
    if not re.fullmatch(r'os-v0\.[0-9]+\.[0-9]+',args.tag):raise ValueError('Invalid tag')
    files={n:download(args.tag,n) for n in ('spot-os-'+args.tag[4:]+'.zip','os-update.json','os-update.json.sig','SHA256SUMS.txt')}
    proof=verify(files,args.tag,args.commit,args.sequence,args.previous,args.fingerprint)
    proof['public_download_without_credentials']=True
    args.output.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof))


if __name__=='__main__':main()
