from dataclasses import dataclass

@dataclass
class RequestLog:
    client_ip: str
    method: str
    path: str
    query_params: str
    user_agent: str
    body: str
