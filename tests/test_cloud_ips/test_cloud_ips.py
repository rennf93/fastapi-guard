from handlers.cloud_handler import (
    CloudManager,
    fetch_aws_ip_ranges,
    fetch_gcp_ip_ranges,
    fetch_azure_ip_ranges,
)
import ipaddress
import pytest
from unittest.mock import patch, Mock


@pytest.fixture
def mock_requests_get():
    with patch("handlers.cloud_handler.requests.get") as mock_get:
        yield mock_get


def test_fetch_aws_ip_ranges(mock_requests_get):
    mock_response = Mock()
    mock_response.json.return_value = {
        "prefixes": [
            {"ip_prefix": "192.168.0.0/24", "service": "AMAZON"},
            {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
        ]
    }
    mock_requests_get.return_value = mock_response

    result = fetch_aws_ip_ranges()
    assert ipaddress.IPv4Network("192.168.0.0/24") in result
    assert ipaddress.IPv4Network("10.0.0.0/8") not in result


def test_fetch_gcp_ip_ranges(mock_requests_get):
    mock_response = Mock()
    mock_response.json.return_value = {
        "prefixes": [{"ipv4Prefix": "172.16.0.0/12"}, {"ipv6Prefix": "2001:db8::/32"}]
    }
    mock_requests_get.return_value = mock_response

    result = fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in result
    assert len(result) == 1


def test_fetch_azure_ip_ranges(mock_requests_get):
    mock_html_response = Mock()
    mock_html_response.text = """
    Some HTML content
    manually <a href="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json">
    More HTML content
    """
    mock_json_response = Mock()
    mock_json_response.json.return_value = {
        "values": [
            {"properties": {"addressPrefixes": ["192.168.1.0/24", "2001:db8::/32"]}}
        ]
    }
    mock_requests_get.side_effect = [mock_html_response, mock_json_response]

    result = fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert len(result) == 1


def test_cloud_ip_ranges():
    with patch("handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws, \
        patch("handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp, \
        patch("handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure:

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_ranges = CloudManager()

        assert cloud_ranges.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_ranges.is_cloud_ip("192.168.0.1", {"GCP"})
        assert cloud_ranges.is_cloud_ip("172.16.0.1", {"GCP"})
        assert cloud_ranges.is_cloud_ip("10.0.0.1", {"Azure"})
        assert not cloud_ranges.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})


@pytest.mark.asyncio
async def test_cloud_ip_refresh():
    with patch("handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws, \
        patch("handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp, \
        patch("handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure:

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_ranges = CloudManager()
        assert cloud_ranges.is_cloud_ip("192.168.0.1", {"AWS"})

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_ranges.refresh()

        assert not cloud_ranges.is_cloud_ip("192.168.0.1", {"AWS"})
        assert cloud_ranges.is_cloud_ip("192.168.1.1", {"AWS"})


def test_cloud_ip_ranges_error_handling():
    with patch(
        "handlers.cloud_handler.fetch_aws_ip_ranges",
        side_effect=Exception("AWS error")
    ), patch(
        "handlers.cloud_handler.fetch_gcp_ip_ranges",
        side_effect=Exception("GCP error")
    ), patch(
        "handlers.cloud_handler.fetch_azure_ip_ranges",
        side_effect=Exception("Azure error")
    ):

        cloud_ranges = CloudManager()

        assert not cloud_ranges.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_ranges.is_cloud_ip("172.16.0.1", {"GCP"})
        assert not cloud_ranges.is_cloud_ip("10.0.0.1", {"Azure"})


def test_cloud_ip_ranges_invalid_ip():
    cloud_ranges = CloudManager()
    assert not cloud_ranges.is_cloud_ip("invalid_ip", {"AWS", "GCP", "Azure"})
