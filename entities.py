from dataclasses import dataclass


@dataclass
class FalcoRule:
    rule: str
    desc: str
    condition: str
    output: str
    priority: str


Rules = dict[str, FalcoRule]
Macros = dict[str, str]
Lists = dict[str, list]