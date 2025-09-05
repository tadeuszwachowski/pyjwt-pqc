import pytest
from jwt.algorithms import get_default_algorithms

def test_dilithium2_sign_verify():
    signer = get_default_algorithms()["DLT2"]

    priv, pub = signer.generate_keypair()
    msg = b"post-quantum test"
    
    sig = signer.sign(msg, priv)
    assert signer.verify(msg, sig, pub)

# def test_falcon512_sign_verify():
#     alg = get_default_algorithms()["FCN512"]

#     priv, pub = alg.generate_keypair()
#     msg = b"falcon signature"

#     sig = alg.sign(msg, priv)
#     assert alg.verify(msg, pub, sig)

# def test_sphincs_sign_verify():
#     alg = get_default_algorithms()["SPNCS"]

#     priv, pub = alg.generate_keypair()
#     msg = b"sphincs+ signature"

#     sig = alg.sign(msg, priv)
#     assert alg.verify(msg, pub, sig)
