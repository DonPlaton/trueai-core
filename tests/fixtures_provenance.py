"""Synthetic, redistributable C2PA fixtures.

Signed test assets are usually borrowed from a vendor's test suite, which makes
them awkward to redistribute and impossible to reason about legally. These are
generated at test time instead: a throwaway root CA, a leaf certificate that
meets the C2PA certificate profile, and an image signed with them. Nothing here
is issued by, or chains to, a real certificate authority, and the trust anchor
returned alongside the asset is the only thing that will ever trust it.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

# Extended key usage required by the C2PA certificate profile for a document
# signing certificate.
DOCUMENT_SIGNING_OID = "1.3.6.1.5.5.7.3.36"
_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
_VALIDITY = datetime.timedelta(days=3650)


@dataclass(frozen=True, slots=True)
class SignedAsset:
    """A signed artifact and the only trust anchor that validates it."""

    path: Path
    trust_anchor_pem: str
    trust_anchor_path: Path
    signer_common_name: str
    manifest_title: str


def provenance_dependencies_available() -> bool:
    """Return whether both the signer and the verifier are installed."""

    import importlib.util

    return all(importlib.util.find_spec(name) is not None for name in ("c2pa", "cryptography"))


def _certificate_name(common_name: str) -> object:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TrueAI Test Fixtures"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )


def build_test_chain() -> tuple[bytes, bytes, bytes]:
    """Return (certificate chain PEM, leaf private key PEM, root PEM)."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _certificate_name("TrueAI Test Root CA")
    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + _VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(_certificate_name("TrueAI Test Signer"))
        .issuer_name(root_certificate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + _VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(DOCUMENT_SIGNING_OID)]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    chain = leaf_certificate.public_bytes(
        serialization.Encoding.PEM
    ) + root_certificate.public_bytes(serialization.Encoding.PEM)
    private_key = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return chain, private_key, root_certificate.public_bytes(serialization.Encoding.PEM)


def build_signed_png(directory: Path, title: str = "Synthetic provenance fixture") -> SignedAsset:
    """Sign a small synthetic PNG with a throwaway chain and return it."""

    import c2pa
    from PIL import Image

    chain, private_key, root_pem = build_test_chain()
    source = directory / "unsigned.png"
    Image.new("RGB", (16, 16), (12, 34, 56)).save(source)
    signed = directory / "signed.png"

    manifest = {
        "claim_generator_info": [{"name": "trueai-test", "version": "0.1.0"}],
        "title": title,
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType": (
                                "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                            ),
                        }
                    ]
                },
            }
        ],
    }
    signer_info = c2pa.C2paSignerInfo(
        alg=b"es256",
        sign_cert=chain,
        private_key=private_key,
        ta_url=None,
    )
    signer = c2pa.Signer.from_info(signer_info)
    with c2pa.Builder(manifest) as builder:
        builder.sign_file(str(source), str(signed), signer)

    anchor_path = directory / "trust-anchor.pem"
    anchor_path.write_bytes(root_pem)
    return SignedAsset(
        path=signed,
        trust_anchor_pem=root_pem.decode("ascii"),
        trust_anchor_path=anchor_path,
        signer_common_name="TrueAI Test Signer",
        manifest_title=title,
    )
