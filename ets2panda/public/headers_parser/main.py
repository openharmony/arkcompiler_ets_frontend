#!/usr/bin/env python3
# coding: utf-8
# Copyright (c) 2024 Huawei Device Co., Ltd.
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


"""
Usage: python3 main.py <path_to_ets2panda> <path_to_gen_dir> <path_to_header_or_dir> [<path_to_header_or_dir> ...]
Description: Parse c++ headers to yaml files.
"""

import os.path
import sys
import traceback
from typing import List

# pylint: disable=W0401,W0614
from cpp_parser import CppParser
from log_tools import init_log, console_log, parsing_log, error_log, info_log
from prepare_header import remove_comments, extract_and_remove_includes
from file_tools import print_to_yaml
from runtime_collections import (
    init_collections,
    add_to_statistics,
    add_to_custom_yamls,
    save_custom_yamls,
    save_statistics,
)


def parse_file(src_path: str, dest_path: str) -> None:
    """
    Parse one file.
    """
    console_log("------------------------------------------------------------------------------")
    parsing_log("Parsing file: " + src_path)

    with open(src_path, "r", encoding="utf-8") as file:
        data = file.read()
        data = remove_comments(data)
        data, includes = extract_and_remove_includes(data)

        try:
            res = CppParser(data).parse()

            if len(includes) != 0:
                res["include"] = includes

            if not os.path.exists(os.path.dirname(dest_path)):
                os.makedirs(os.path.dirname(dest_path))

            print_to_yaml(dest_path, res)
            console_log("\n++++++++++++++++++++++++\n+ Successfully parsed! +\n++++++++++++++++++++++++")

            # Collect statistics
            add_to_statistics("generated_yamls", dest_path)
            # Collect custom yamls
            add_to_custom_yamls("pathsToHeaders", "paths", src_path)

        except Exception:  # pylint: disable=W0718
            os.fdopen(os.open(dest_path, os.O_CREAT, mode=511), "w", encoding="utf-8").close()

            error_log("Error while parsing '" + src_path + "'\n")
            error_log(traceback.format_exc() + "\n")
            info_log("Error! Can't parse '" + src_path + "'")


def parse_files_in_list(paths_list: List[str], result_folder: str) -> None:
    """
    Parse all headers from paths_list. Elements of list can be file's or dir's paths.
    """
    os.makedirs(result_folder, exist_ok=True)

    for path in paths_list:
        if os.path.isdir(path):

            if path.rstrip("/") == result_folder.rstrip("/"):
                continue

            nested_paths = [os.path.join(path, dir_file) for dir_file in os.listdir(path)]
            parse_files_in_list(nested_paths, result_folder)

        elif os.path.isfile(path) and os.path.splitext(path)[1] == ".h":
            dst = os.path.join(result_folder, f"{os.path.splitext(os.path.relpath(path, sys.argv[1]))[0]}.yaml")
            parse_file(path, dst)

        else:
            info_log(f"Error! File does not fit for parsing or does not exist: '{path}'")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise RuntimeError("Wrong arguments!")

    lib_gen_dir = sys.argv[2]
    if not os.path.exists(lib_gen_dir) or not os.path.isdir(lib_gen_dir):
        raise RuntimeError(f"Please change lib_gen_dir to correct path.\n'{lib_gen_dir}'")
    init_collections(lib_gen_dir)
    init_log(lib_gen_dir)

    files_list = list(sys.argv[3:])
    parse_files_in_list(files_list, os.path.join(lib_gen_dir, "gen/headers"))
    save_custom_yamls()
    save_statistics()
