#!/usr/bin/env python3
"""Small YAML 1.2-compatible safe loader for repository planning artifacts.

PyYAML's default resolver follows YAML 1.1 and interprets values such as `YES`
and `NO` as booleans. HeptaBao inventories use those values as explicit enum
labels, so this loader recognizes only true/false spellings as booleans.
"""

from __future__ import annotations

import copy
import re
from typing import Any

import yaml


class Yaml12SafeLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 boolean resolution."""


Yaml12SafeLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for first_character, resolvers in list(Yaml12SafeLoader.yaml_implicit_resolvers.items()):
    Yaml12SafeLoader.yaml_implicit_resolvers[first_character] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]

Yaml12SafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def safe_load_yaml12(text: str) -> Any:
    return yaml.load(text, Loader=Yaml12SafeLoader)
