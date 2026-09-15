import time
import requests
from typing import Dict, Any, Optional, Tuple

class APIManager:
    """
    A simple API manager with support for custom headers, automatic retries, and exponential backoff.
    """
    def __init__(
        self,
        base_url: str,
        custom_headers: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        timeout: Optional[float] = 10.0,
    ):
        """
        :param base_url: Base URL for the API.
        :param custom_headers: Optional dictionary of headers to include with every request.
        :param max_retries: Maximum number of retry attempts for failed requests.
        :param backoff_factor: Base factor for exponential backoff in seconds.
        :param timeout: Request timeout in seconds.
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update(custom_headers or {})
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.timeout = timeout

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], str]:
        """
        Internal method to perform a request with retry logic.
        :return: (status_code, response_headers, response_text)
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        attempt = 0
        while True:
            try:
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp.status_code, resp.headers, resp.text
            except requests.RequestException as exc:
                attempt += 1
                if attempt > self.max_retries:
                    raise
                backoff = self.backoff_factor * (2 ** (attempt - 1))
                time.sleep(backoff)

    def get(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], str]:
        return self._request("GET", endpoint, params=params, headers=headers)

    def post(
        self,
        endpoint: str,
        *,
        data: Any = None,
        json: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], str]:
        return self._request("POST", endpoint, data=data, json=json, headers=headers)

    def put(
        self,
        endpoint: str,
        *,
        data: Any = None,
        json: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], str]:
        return self._request("PUT", endpoint, data=data, json=json, headers=headers)

    def delete(
        self,
        endpoint: str,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, Any], str]:
        return self._request("DELETE", endpoint, headers=headers)

# ------------------- Testing Block -------------------
import unittest
from unittest.mock import patch, MagicMock

class TestAPIManager(unittest.TestCase):
    def setUp(self):
        self.manager = APIManager(
            base_url="https://api.example.com",
            custom_headers={"Authorization": "Bearer token"},
            max_retries=2,
            backoff_factor=0.1,
        )

    @patch.object(requests.Session, "request")
    def test_get_success(self, mock_request):
        # Mock a successful response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.text = '{"key": "value"}'
        mock_resp.raise_for_status.return_value = None
        mock_request.return_value = mock_resp

        status, headers, body = self.manager.get("/resource")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(body, '{"key": "value"}')
        mock_request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/resource",
            params=None,
            data=None,
            json=None,
            headers=None,
            timeout=10.0,
        )

    @patch.object(requests.Session, "request")
    def test_retry_logic(self, mock_request):
        # Simulate two failures followed by a success
        failure_resp = MagicMock()
        failure_resp.raise_for_status.side_effect = requests.HTTPError("500 Internal Server Error")

        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.headers = {}
        success_resp.text = ""
        success_resp.raise_for_status.return_value = None

        mock_request.side_effect = [failure_resp, failure_resp, success_resp]

        status, _, _ = self.manager.get("/unstable")
        self.assertEqual(status, 200)
        self.assertEqual(mock_request.call_count, 3)

    @patch.object(requests.Session, "request")
    def test_exceeded_retries(self, mock_request):
        # Simulate all failures
        failure_resp = MagicMock()
        failure_resp.raise_for_status.side_effect = requests.HTTPError("500 Internal Server Error")
        mock_request.side_effect = [failure_resp] * (self.manager.max_retries + 1)

        with self.assertRaises(requests.HTTPError):
            self.manager.get("/always-fail")
        self.assertEqual(mock_request.call_count, self.manager.max_retries + 1)

if __name__ == "__main__":
    unittest.main(verbosity=2)