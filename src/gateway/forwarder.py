import requests

def forward_request(method, url, headers, params, body):
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=body,
            timeout=5
        )
        return response.status_code, response.headers, response.content
    except Exception as e:
        return 502, {}, b"Bad Gateway"
