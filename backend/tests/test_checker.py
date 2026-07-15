import socket
import pytest
import requests
import whois
from datetime import datetime
from backend.checker import resolve_dns, check_crt_sh, normalize_date, query_whois, check_domain

def test_resolve_dns_success(mocker):
    # Mock socket.gethostbyname to simulate successful DNS resolution
    mock_gethost = mocker.patch("socket.gethostbyname", return_value="192.168.1.1")
    assert resolve_dns("example.com") is True
    mock_gethost.assert_called_once_with("example.com")

def test_resolve_dns_failure(mocker):
    # Mock socket.gethostbyname to throw a gaierror
    mock_gethost = mocker.patch("socket.gethostbyname", side_effect=socket.gaierror())
    assert resolve_dns("nonexistent.example") is False
    mock_gethost.assert_called_once_with("nonexistent.example")

def test_check_crt_sh_confirmed(mocker):
    # Mock requests.get returning valid JSON list
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"common_name": "example.com"}]
    mock_get = mocker.patch("requests.get", return_value=mock_response)

    assert check_crt_sh("example.com") == "confirmed"
    mock_get.assert_called_once()

def test_check_crt_sh_not_found(mocker):
    # Mock requests.get returning empty JSON list
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_get = mocker.patch("requests.get", return_value=mock_response)

    assert check_crt_sh("example.com") == "not_found"

def test_check_crt_sh_retry_and_success(mocker):
    # Mock requests.get to fail first, then succeed
    mock_fail = mocker.Mock()
    mock_fail.status_code = 500
    
    mock_success = mocker.Mock()
    mock_success.status_code = 200
    mock_success.json.return_value = [{"common_name": "example.com"}]
    
    # We call requests.get 3 times: fail, fail, success
    mock_get = mocker.patch("requests.get", side_effect=[requests.RequestException("Timeout"), mock_fail, mock_success])
    mock_sleep = mocker.patch("time.sleep")  # avoid actual waiting in tests

    assert check_crt_sh("example.com") == "confirmed"
    assert mock_get.call_count == 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_has_calls([mocker.call(1.0), mocker.call(2.0)])

def test_check_crt_sh_unknown_after_retries(mocker):
    # Mock requests.get to always raise RequestException
    mock_get = mocker.patch("requests.get", side_effect=requests.RequestException("Connection error"))
    mock_sleep = mocker.patch("time.sleep")

    assert check_crt_sh("example.com") == "unknown"
    assert mock_get.call_count == 3

def test_normalize_date_scenarios():
    # String dates
    assert normalize_date("2026-06-20") == datetime(2026, 6, 20)
    
    # Datetime objects
    dt = datetime(2025, 12, 31, 10, 0, 0)
    assert normalize_date(dt) == dt
    
    # Lists
    dt_list = [datetime(2026, 1, 15), datetime(2026, 3, 20)]
    assert normalize_date(dt_list) == datetime(2026, 1, 15)
    
    # Invalid strings/types
    assert normalize_date("invalid-date") is None
    assert normalize_date(12345678) is None
    assert normalize_date(None) is None

def test_query_whois_success(mocker):
    # Mock python-whois response object
    mock_whois_data = {
        "creation_date": [datetime(2026, 6, 20), datetime(2026, 7, 1)],
        "registrar": "NameCheap Inc."
    }
    mocker.patch("whois.whois", return_value=mock_whois_data)
    
    reg_date, registrar = query_whois("example.com")
    assert reg_date == "2026-06-20"
    assert registrar == "NameCheap Inc."

def test_query_whois_failure_handling(mocker):
    # Mock whois.whois raising exception
    mocker.patch("whois.whois", side_effect=Exception("WHOIS server down"))
    
    reg_date, registrar = query_whois("example.com")
    assert reg_date is None
    assert registrar is None

def test_check_domain_unflagged(mocker):
    # Domain not resolved, certificate not found -> not flagged, no WHOIS queried
    mocker.patch("backend.checker.resolve_dns", return_value=False)
    mocker.patch("backend.checker.check_crt_sh", return_value="not_found")
    mock_whois = mocker.patch("backend.checker.query_whois")
    
    res = check_domain("unflagged.com", ["omission"])
    assert res["dns_resolves"] is False
    assert res["certificate_status"] == "not_found"
    assert res["registered_date"] is None
    assert res["registrar"] is None
    mock_whois.assert_not_called()

def test_check_domain_flagged(mocker):
    # Domain resolves -> flagged -> WHOIS is queried
    mocker.patch("backend.checker.resolve_dns", return_value=True)
    mocker.patch("backend.checker.check_crt_sh", return_value="confirmed")
    mock_whois = mocker.patch("backend.checker.query_whois", return_value=("2026-06-20", "NameCheap Inc."))
    
    res = check_domain("flagged.com", ["prefix"])
    assert res["dns_resolves"] is True
    assert res["certificate_status"] == "confirmed"
    assert res["registered_date"] == "2026-06-20"
    assert res["registrar"] == "NameCheap Inc."
    mock_whois.assert_called_once_with("flagged.com")
