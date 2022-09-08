import pytest
from https import server

def test_parse_args_exit_codes():
    with pytest.raises(SystemExit) as e:
        server.parse_args(["--key", "test/test.key"])
    assert e.type == SystemExit
    assert e.value.code == 1
