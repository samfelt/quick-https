import pytest
from https import server

TEST_KEY = "tests/files/test.key"
TEST_CERT = "tests/files/test.crt"


@pytest.mark.parametrize(
    ("input_msg", "input_suppress", "expected"),
    (
        pytest.param("TEST", True, "    TEST", id="suppress"),
        pytest.param("TEST", False, "[+] TEST", id="not_suppress"),
    )
)
def test_verbose_print(input_msg, input_suppress, expected, capsys):
    server.VERBOSE = True
    server.verbose_print(input_msg, input_suppress)
    captured = capsys.readouterr()
    assert captured.out[0:4] == expected[0:4]
    assert captured.out[4:] == f"{expected[4:]}\n"


def test_verbose_print_verbose_off(capsys):
    server.VERBOSE = False 
    server.verbose_print("TEST")
    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.parametrize(
    ("input_args", "expected_output_code"),
    (
        pytest.param(["--help"], 0, id="print_help"),
        pytest.param(["--key", "test.key"], 1, id="only_key"),
        pytest.param(["--cert", "test.crt"], 1, id="only_cert"),
        pytest.param(["--key", TEST_KEY, "--cert", "nothere"], 1, id="missing_cert"),
        pytest.param(["--key", "nothere", "--cert", TEST_CERT], 1, id="missing_key"),
    )
)
def test_parse_args_exit_codes(input_args, expected_output_code):
    with pytest.raises(SystemExit) as e:
        server.parse_args(input_args)
    assert e.type == SystemExit
    assert e.value.code == expected_output_code
