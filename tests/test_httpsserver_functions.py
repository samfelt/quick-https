import pytest
from https import HTTPSServer

def test_different_serial_numbers():
    key1, cert1 = HTTPSServer.generate_self_signed_cert()
    key2, cert2 = HTTPSServer.generate_self_signed_cert()
    assert cert1.serial_number != cert2.serial_number
