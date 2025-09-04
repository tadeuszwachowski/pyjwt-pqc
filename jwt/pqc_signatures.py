from oqs import Signature

# Initialize post-quantum signature schemes
Dilithium2 = Signature("Dilithium2")
Dilithium3 = Signature("Dilithium3")
Dilithium5 = Signature("Dilithium5")
Falcon512 = Signature("Falcon-512")
Falcon1024 = Signature("Falcon-1024")
SphincsS = Signature("SPHINCS+-SHA2-128s-simple")

class Dilithium2PrivateKey:
    def __init__(self):
        self._sig = Signature("Dilithium2")
        self._pk = signer.generate_keypair()
        self._sk = signer.export_secret_key()

    def sign(self, data: bytes) -> bytes:
        return self._sig.sign(data)

    def public_key(self):
        return Dilithium2PublicKey(self._sig)


class Dilithium2PublicKey:
    def __init__(self, sig: Signature, pk: bytes):
        self._sig = sig
        self._pk = self._sig.generate_keypair()

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._sig.verify(data, signature, self._pk)
        except Exception:
            return False

class Dilithium3PrivateKey:
    def __init__(self):
        self._sig = Signature("Dilithium3")
        self._pk = signer.generate_keypair()
        self._sk = signer.export_secret_key()

    def sign(self, data: bytes) -> bytes:
        return self._sig.sign(data)

    def public_key(self):
        return Dilithium2PublicKey(self._sig)


class Dilithium3PublicKey:
    def __init__(self, sig: Signature, pk: bytes):
        self._sig = sig
        self._pk = self._sig.generate_keypair()

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._sig.verify(data, signature, self._pk)
        except Exception:
            return False

class Dilithium5PrivateKey:
    def __init__(self):
        self._sig = Signature("Dilithium5")
        self._pk = signer.generate_keypair()
        self._sk = signer.export_secret_key()

    def sign(self, data: bytes) -> bytes:
        return self._sig.sign(data)

    def public_key(self):
        return Dilithium2PublicKey(self._sig)


class Dilithium5PublicKey:
    def __init__(self, sig: Signature, pk: bytes):
        self._sig = sig
        self._pk = self._sig.generate_keypair()

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._sig.verify(data, signature, self._pk)
        except Exception:
            return False

class Falcon512PrivateKey:
    def __init__(self):
        self._sig = Signature("Falcon-512")
        self._pk = signer.generate_keypair()
        self._sk = signer.export_secret_key()

    def sign(self, data: bytes) -> bytes:
        return self._sig.sign(data)

    def public_key(self):
        return Dilithium2PublicKey(self._sig)

class Falcon512PublicKey:
    def __init__(self, sig: Signature, pk: bytes):
        self._sig = sig
        self._pk = self._sig.generate_keypair()

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._sig.verify(data, signature, self._pk)
        except Exception:
            return False

class Falcon1024PrivateKey:
    def __init__(self):
        self._sig = Signature("Falcon-1024")
        self._pk = signer.generate_keypair()
        self._sk = signer.export_secret_key()

    def sign(self, data: bytes) -> bytes:
        return self._sig.sign(data)

    def public_key(self):
        return Dilithium2PublicKey(self._sig)


class Falcon1024PublicKey:
    def __init__(self, sig: Signature, pk: bytes):
        self._sig = sig
        self._pk = self._sig.generate_keypair()

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._sig.verify(data, signature, self._pk)
        except Exception:
            return False

class SphincsSPrivateKey:
    def __init__(self):
        self._sig = Signature("SPHINCS+-SHA2-128s-simple")
        self._pk = signer.generate_keypair()
        self._sk = signer.export_secret_key()

    def sign(self, data: bytes) -> bytes:
        return self._sig.sign(data)

    def public_key(self):
        return Dilithium2PublicKey(self._sig)


class SphincsSPublicKey:
    def __init__(self, sig: Signature, pk: bytes):
        self._sig = sig
        self._pk = self._sig.generate_keypair()

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._sig.verify(data, signature, self._pk)
        except Exception:
            return False

# Export these for use in other modules
__all__ = [
    "Dilithium2",
    "Dilithium2PrivateKey",
    "Dilithium2PublicKey",
    "Dilithium3",
    "Dilithium3PrivateKey",
    "Dilithium3PublicKey",
    "Dilithium5",
    "Dilithium5PrivateKey",
    "Dilithium5PublicKey",
    "Falcon512",
    "Falcon512PrivateKey",
    "Falcon512PublicKey",
    "Falcon1024",
    "Falcon1024PrivateKey",
    "Falcon1024PublicKey",
    "SphincsS",
    "SphincsSPrivateKey",
    "SphincsSPublicKey",
]
# __all__ = [
#     "Dilithium2PrivateKey",
#     "Dilithium2PublicKey",
# ]