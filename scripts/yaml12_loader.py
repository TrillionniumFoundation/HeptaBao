#!/usr/bin/env python3
"""Small YAML 1.2-compatible safe loader for repository planning artifacts.

PyYAML's default resolver follows YAML 1.1 and interprets values such as `YES`
and `NO` as booleans. HeptaBao inventories use those values as explicit enum
labels, so this loader recognizes only true/false spellings as booleans.
Validators that also reject duplicate keys use UniqueKeyYaml12Loader; the
permissive safe_load_yaml12 entry point keeps its existing mapping semantics.
"""

from __future__ import annotations

import copy
import re
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver


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


class UniqueKeyYaml12Loader(Yaml12SafeLoader):
    """YAML 1.2 loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyYaml12Loader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyYaml12Loader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def safe_load_yaml12(text: str) -> Any:
    return yaml.load(text, Loader=Yaml12SafeLoader)
