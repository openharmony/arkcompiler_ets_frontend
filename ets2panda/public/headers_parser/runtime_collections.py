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


"""This module provides structures, to save some info while parsing headers."""

import os
import sys
from typing import Any, Dict
from file_tools import print_to_yaml
from log_tools import info_log

statistics: Dict[str, Dict[str, Any]] = {}
custom_yamls: Dict[str, Dict[str, Any]] = {}
LIB_GEN_FOLDER = ""


def init_collections(lib_gen_folder: str) -> None:  # pylint: disable=C
    global statistics, custom_yamls, LIB_GEN_FOLDER  # pylint: disable=W
    LIB_GEN_FOLDER = lib_gen_folder

    statistics = {
        "unreachable": {
            "log_file": LIB_GEN_FOLDER + "/gen/logs/unreachable.txt",
            "collection": set(),
        },
        "skip": {
            "log_file": LIB_GEN_FOLDER + "/gen/logs/skip.txt",
            "collection": set()
        },
        "generated_yamls": {
            "log_file": LIB_GEN_FOLDER + "/gen/logs/generated_yamls.txt",
            "collection": set(),
        },
    }

    custom_yamls = {
        "allEnums": {
            "yaml_file": LIB_GEN_FOLDER + "/gen/headers/allEnums.yaml",
            "collection": {"enums": []},
        },
        "pathsToHeaders": {
            "yaml_file": LIB_GEN_FOLDER + "/gen/headers/pathsToHeaders.yaml",
            "collection": {"paths": []},
        },
    }


def add_to_statistics(key: str, data: Any) -> None:
    if isinstance(statistics[key]["collection"], set):
        statistics[key]["collection"].add(data)
    elif isinstance(statistics[key]["collection"], list):
        statistics[key]["collection"].append(data)
    else:
        raise RuntimeError("Unreachable")


def add_to_custom_yamls(yaml_name: str, key: str, data: Any) -> None:
    custom_yamls[yaml_name]["collection"][key].append(data)


def save_custom_yamls() -> None:
    if not os.path.exists(LIB_GEN_FOLDER + "/gen/headers"):
        os.makedirs(LIB_GEN_FOLDER + "/gen/headers")

    for _, value in custom_yamls.items():
        print_to_yaml(value["yaml_file"], value["collection"])
        info_log("Saved custom yaml: '" + value["yaml_file"] + "'")

        statistics["generated_yamls"]["collection"].add(
            os.path.basename(value["yaml_file"])
        )


def save_statistics() -> None:
    if not os.path.exists(LIB_GEN_FOLDER + "/gen/logs"):
        os.makedirs(LIB_GEN_FOLDER + "/gen/logs")

    info_log(f"Parsed {len(custom_yamls['pathsToHeaders']['collection']['paths'])} / {len(sys.argv[3:])} headers.")

    for _, value in statistics.items():
        with open(value["log_file"], "w", encoding="utf-8") as f:
            for item in value["collection"]:
                f.write(item + "\n")