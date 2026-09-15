import logging
import json
from typing import Any, Dict, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure module-level logger
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

class APIError(Exception):
    """Base class for API related errors."""
    def __init__(self, status_code: Optional[int] = None, message: str = "", response: Optional[requests.Response] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class APIManager:
    """
    A robust API client wrapper that supports GET, POST, PUT, DELETE
    operations with comprehensive logging, retry logic, and edge case handling.
    """

    def __init__(
        self,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Union[float, tuple] = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
        status_forcelist: Optional[tuple] = (500, 502, 504),
        auth: Optional[Any] = None,
        session: Optional[requests.Session] = None,
        *,
        raise_on_status: bool = True,
    ) -> None:
        """
        :param base_url: Base URL for the API, e.g., "https://api.example.com".
        :param headers: Default headers to send with each request.
        :param timeout: Timeout for HTTP requests. Can be a single float or a (connect, read) tuple.
        :param max_retries: Number of retries on failed requests.
        :param backoff_factor: Backoff factor for retries.
        :param status_forcelist: HTTP status codes to trigger a retry.
        :param auth: Authentication tuple or requests.AuthBase instance.
        :param session: Optional requests.Session to use.
        :param raise_on_status: If True, raise APIError on non-success status codes.
        """
        if not isinstance(base_url, str) or not base_url:
            raise ValueError("base_url must be a non-empty string")

        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self.auth = auth
        self.raise_on_status = raise_on_status

        self.session = session or requests.Session()
        # Mount HTTPAdapter with retries
        retry = Retry(
            total=max_retries,
            read=max_retries,
            connect=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        logger.debug(
            "APIManager initialized: base_url=%s, timeout=%s, max_retries=%s, headers=%s",
            self.base_url,
            self.timeout,
            max_retries,
            self.headers,
        )

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        if not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string")

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        merged_headers = self.headers.copy()
        if headers:
            merged_headers.update(headers)

        logger.debug(
            "Preparing %s request to %s with params=%s, data=%s, json_data=%s, headers=%s",
            method.upper(),
            url,
            params,
            data,
            json_data,
            merged_headers,
        )

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=merged_headers,
                timeout=self.timeout,
                auth=self.auth,
            )
        except requests.RequestException as exc:
            logger.error("RequestException for %s %s: %s", method.upper(), url, exc)
            raise APIError(message=str(exc)) from exc

        logger.debug(
            "Received response: status_code=%s, headers=%s, text=%s",
            response.status_code,
            response.headers,
            response.text[:200],
        )

        if self.raise_on_status and not response.ok:
            logger.warning(
                "Non-success status code %s for %s %s: %s",
                response.status_code,
                method.upper(),
                url,
                response.text[:200],
            )
            raise APIError(
                status_code=response.status_code,
                message=f"HTTP {response.status_code} for {method.upper()} {url}",
                response=response,
            )

        content_type = response.headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            try:
                return response.json()
            except json.JSONDecodeError as exc:
                logger.error("JSON decode error for %s %s: %s", method.upper(), url, exc)
                raise APIError(
                    status_code=response.status_code,
                    message="Invalid JSON response",
                    response=response,
                ) from exc
        else:
            return response.text

    # Public HTTP verb methods

    def get(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return self._request("GET", endpoint, params=params, headers=headers)

    def post(
        self,
        endpoint: str,
        *,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return self._request("POST", endpoint, data=data, json_data=json_data, headers=headers)

    def put(
        self,
        endpoint: str,
        *,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return self._request("PUT", endpoint, data=data, json_data=json_data, headers=headers)

    def delete(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return self._request("DELETE", endpoint, params=params, headers=headers)

    # Context manager support

    def __enter__(self) -> "APIManager":
        logger.debug("Entering context manager for APIManager")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        logger.debug("Exiting context manager for APIManager, closing session")
        self.session.close()