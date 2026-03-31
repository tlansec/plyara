# Copyright 2014 Christian Buia
# Copyright 2025 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""plyara types.

This module contains type definitions for plyara's parsed YARA rule output.
"""
from typing import TypedDict

MetaValue = str | int | bool


class _YaraStringEntryRequired(TypedDict):
    name: str
    value: str
    type: str


class YaraStringEntry(_YaraStringEntryRequired, total=False):
    """Represent a parsed YARA string definition."""

    modifiers: list[str]


class _YaraRuleRequired(TypedDict):
    rule_name: str
    start_line: int
    stop_line: int
    condition_terms: list[str]


class YaraRule(_YaraRuleRequired, total=False):
    """Represent a parsed YARA rule."""

    imports: list[str]
    includes: list[str]
    scopes: list[str]
    tags: list[str]
    comments: list[str]
    metadata: list[dict[str, MetaValue]]
    metadata_kv: dict[str, MetaValue]
    strings: list[YaraStringEntry]
    raw_meta: str
    raw_strings: str
    raw_condition: str
