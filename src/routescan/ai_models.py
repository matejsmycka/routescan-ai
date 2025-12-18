from dataclasses import dataclass
from typing import Optional

from routescan.models import Route


@dataclass
class EndpointInput:
    route: Route
    http_method: Optional[str]
    source_summary: str
    parameters: list[str]


@dataclass
class RouteFlow:
    route: Route
    endpoint_input: EndpointInput
    sink_summary: str
    call_stack: str


@dataclass
class SecurityIssue:
    route: Route
    severity: str
    title: str
    description: str
    payload: str
    poc_info: str


