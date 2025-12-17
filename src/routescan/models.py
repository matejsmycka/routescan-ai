from dataclasses import dataclass
from typing import Optional
import re


@dataclass
class Route:
    project: str
    file: str
    line: int
    endpoint: str


@dataclass
class RoutePattern:
    regex: re.Pattern
    endpoint_group: Optional[str]


