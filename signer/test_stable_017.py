"""Explicit operator stable gate; ephemeral test identity, never production secrets."""
from unittest import TestCase
import sign_candidate as signer
import verify_public as verifier
import test_verify_public as public_tests


class Public017VerificationTests(public_tests.Public016VerificationTests):
    VERSION='0.1.7'
    SEQUENCE=107
    PREVIOUS='0.1.6'
    CHANNEL='stable'

    def test_github_marking_must_match_signed_stable_channel(self):
        for field,value in (('prerelease',True),('draft',True),('tag_name','os-v0.1.6')):
            release=dict(tag_name='os-v0.1.7',draft=False,prerelease=False)
            release[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'marking'):
                verifier.verify(self.assets(),'os-v0.1.7','a'*40,107,'0.1.6',self.fingerprint,release)
        proof=verifier.verify(self.assets(),'os-v0.1.7','a'*40,107,'0.1.6',self.fingerprint,
            dict(tag_name='os-v0.1.7',draft=False,prerelease=False))
        self.assertFalse(proof['prerelease'])


class StableGateTests(TestCase):
    def test_exact_stable_tuple_and_both_independent_operator_gates(self):
        self.assertTrue(signer.release_target_valid('0.1.7',107,'0.1.6','os-v0.1.7'))
        self.assertTrue(signer.channel_valid('0.1.7','stable','true','true'))
        for enabled,hardware in (('',''),('true',''),('','true'),('false','true'),('true','false')):
            with self.subTest(enabled=enabled,hardware=hardware):
                self.assertFalse(signer.channel_valid('0.1.7','stable',enabled,hardware))
        self.assertFalse(signer.channel_valid('0.1.7','prerelease','true','true'))
        for version in ('0.1.4','0.1.5','0.1.6'):
            self.assertTrue(signer.channel_valid(version,'prerelease'))
            self.assertFalse(signer.channel_valid(version,'stable','true','true'))
        for seq,previous in ((106,'0.1.6'),(108,'0.1.6'),(107,'0.1.4'),(107,'0.1.5'),(107,'0.1.7')):
            self.assertFalse(signer.release_target_valid('0.1.7',seq,previous,'os-v0.1.7'))
