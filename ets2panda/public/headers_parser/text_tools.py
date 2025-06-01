#!/usr/bin/env python3
# coding=utf-8
#
# Copyright (c) 2024-2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Module provides custom text tools for parsing."""

from typing import Tuple, Dict
from log_tools import debug_log


MAX_LEN = 10000000


def find_first_not_restricted_character(restricted: str, data: str, pos: int = 0, pos_end: int = MAX_LEN) -> int:
    for i in range(pos, min(len(data), pos_end)):
        if data[i] not in restricted:
            return i
    return len(data)


def rfind_first_not_restricted_character(restricted: str, data: str, pos: int, pos_end: int = 0) -> int:
    """pos_end includes in searching"""
    if pos > len(data):
        pos = len(data) - 1
    while pos >= max(0, pos_end):
        if data[pos] not in restricted:
            return pos
        pos -= 1
    return len(data)


def skip_rstring(data: str, pos: int = 0, pos_end: int = MAX_LEN) -> int:
    """Returns next position after R-string, start pos if no R-string found"""
    if data[pos] != '"' or pos < 1:
        return pos

    if data[pos - 1 : pos + 1] == 'R"':
        start_of_string_data = data.find("(", pos)
        if start_of_string_data == -1:
            raise RuntimeError("Error while finding start of R-string.")

        delimeter = f"{data[pos + 1 : start_of_string_data]}"
        end_of_string_data = data.find(f'){delimeter}"', start_of_string_data)

        if end_of_string_data == -1 or end_of_string_data >= min(len(data), pos_end):
            raise RuntimeError("Error while finding end of R-string.")

        return end_of_string_data + len(f'){delimeter}"')

    return pos


def skip_string(data: str, pos: int = 0, pos_end: int = MAX_LEN) -> int:
    """Returns next position after string, raise Runtime error if no string found"""
    if data[pos] not in "'\"":
        return pos

    current_quote = data[pos]
    pos = data.find(current_quote, pos + 1)

    # Skip escaped quotes
    while pos > 0 and pos < min(len(data), pos_end) and data[pos - 1] == "\\" and (pos == 1 or data[pos - 2] != "\\"):
        pos = data.find(current_quote, pos + 1)

    if pos == -1 or pos >= min(len(data), pos_end):
        raise RuntimeError("Error while finding end of string.")
    return pos + 1


def find_first_of_characters(characters: str, data: str, pos: int = 0, pos_end: int = MAX_LEN) -> int:
    while pos < min(len(data), pos_end) and pos != -1:
        # Skip strings (if we are not looking for quotes)
        if "'" not in characters and '"' not in characters and data[pos] in "'\"":
            pos = skip_rstring(data, pos)
            pos = skip_string(data, pos)
            continue
        if data[pos] in characters:
            return pos
        pos += 1
    return len(data)


def rfind_first_of_characters(characters: str, data: str, pos: int, pos_end: int = 0) -> int:
    """pos_end includes in searching"""
    if pos > len(data):
        pos = len(data) - 1
    while pos >= max(0, pos_end):
        if data[pos] in characters:
            return pos
        pos -= 1
    return len(data)


def is_operator(data: str, current_pos: int) -> bool:
    if current_pos < len("operator") + 1 or data[current_pos - len("operator") - 1].isalpha():
        return False
    return data[current_pos - len("operator") : current_pos] == "operator"


def find_scope_borders(data: str, start: int = 0, opening_bracket: str = "{") -> Tuple[int, int]:
    """
    Returns tuple of positions of opening and closing brackets in 'data'.
    Raises RuntimeError if can't find scope borders.
    """
    brackets_match: Dict[str, str] = {"{": "}", "(": ")", "<": ">", "[": "]"}
    opening = opening_bracket
    start_of_scope = start

    while not opening:
        start_of_scope = find_first_of_characters("({<[", data, start_of_scope)
        if start_of_scope == len(data):
            raise RuntimeError("No opening bracket found in ANY mode")
        if is_operator(data, start_of_scope):
            start_of_scope = find_first_not_restricted_character(data[start_of_scope], data, start_of_scope + 1)
        else:
            opening = data[start_of_scope]

    start_of_scope = data.find(opening, start)

    while is_operator(data, start_of_scope):
        start_of_scope = find_first_not_restricted_character(opening, data, start_of_scope + 1)
        start_of_scope = find_first_of_characters(opening, data, start_of_scope)

    if start_of_scope == -1:
        raise RuntimeError("No opening bracket found")

    current_pos = start_of_scope
    closing = brackets_match[opening]
    bracket_sequence_sum = 1

    while bracket_sequence_sum != 0:
        current_pos = find_first_of_characters(f"{opening}{closing}", data, current_pos + 1)
        if current_pos == len(data):
            raise RuntimeError("Error while finding end of scope.")
        if data[current_pos] == opening:
            bracket_sequence_sum += 1
        elif data[current_pos] == closing:
            bracket_sequence_sum -= 1

    return start_of_scope, current_pos


def smart_split_by(data: str, delim: str = ",") -> list:
    data = data.strip(" \n")

    res = []
    segment_start = 0

    while segment_start < len(data):

        next_delim = smart_find_first_of_characters(delim, data, segment_start)

        segment = data[segment_start:next_delim].strip(" \n")
        if segment != "":
            res.append(segment)
        else:
            debug_log("Empty segment in smart_split_by.")

        segment_start = find_first_not_restricted_character(f"{delim} \n", data, next_delim)

    return res


def smart_find_first_of_characters(characters: str, data: str, pos: int) -> int:
    i = pos
    while i < len(data):
        if data[i] in characters:
            return i

        if data[i] in "<({[":
            _, close_bracket = find_scope_borders(data, i, "")
            i = close_bracket

        elif data[i] == '"':
            i = data.find('"', i + 1)
            while i != -1 and data[i] == '"' and i != 0 and data[i - 1] == "\\":
                i = data.find('"', i + 1)

        elif data[i] == "'":
            i = data.find("'", i + 1)

        i += 1

    return len(data)


def check_cpp_name(data: str) -> bool:
    data = data.lower()
    forbidden_chars = " ~!@#$%^&*()-+=[]\\{}|;:'\",./<>?"
    return find_first_of_characters(forbidden_chars, data) == len(data)
