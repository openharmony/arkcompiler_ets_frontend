#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

import re
import argparse
import subprocess
import time

from enum import Enum


class TestTypes(Enum):
    NORMAL = 0
    CLANGTIDY = 1
    CLANGFORMAT = 2


def print_summary(log_lines, searched_words, end_word=""):
    was_any_log = False
    should_print = False

    for line in log_lines:
        for word in searched_words:
            if any(word in line for word in searched_words):
                should_print = True
                was_any_log = True

        if end_word and end_word in line:
            should_print=False

        if should_print:
            print(line.strip())

    if not was_any_log:
        print("Problem occourd: ", was_any_log)

    print(f"\n")


def print_progress_to_console(line, test_type, pattern_progress_bar, pattern_clang_tidy, pattern_clang_format):
    match test_type:
        case TestTypes.NORMAL:
            match = pattern_progress_bar.search(line)
            if match:
                print(line, end='')
        case TestTypes.CLANGTIDY:
            match = re.match(pattern_clang_tidy, line)
            if match:
                print(f"[{match.group(1)}/{match.group(2)}] {match.group(3)}")
        case TestTypes.CLANGFORMAT:
            match = re.match(pattern_clang_format, line)
            if match:
                print(f"[{match.group(1)}/{match.group(2)}] Clang-format: {match.group(3)} \n")


def test_process_runner(runtime_process, test_type):
    pattern_progress_bar = re.compile(r'\b(\d{1,3}%)\|(.+?)\| (\d+)/(\d+) \[\d{2}:\d{2}<\d{2}:\d{2},\s*\d+\.\d+it/s\]$')
    pattern_clang_tidy = re.compile(r"^\[(\d+)\/(\d+)\]\s+Done\s+clang-tidy:\s+.*?\/es2panda\/(.+\.cpp)$")
    pattern_clang_format = re.compile(r"\[(\d+)/(\d+)\]\s+Running clang-format: (.+)")

    should_print = False
    log_lines = []

    for line in runtime_process.stdout:
        log_lines.append(line)
        print_progress_to_console(line, test_type, pattern_progress_bar, pattern_clang_tidy, pattern_clang_format)

    return log_lines


def command_runner(command_to_run, test_type):
    try:
        process = subprocess.Popen(command_to_run, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        process_log = test_process_runner(process, test_type)

    except subprocess.CalledProcessError as e:
        process_log = str(e)
        print("An error occurred during processing:", process_log)

    except Exception as e:
        process_log = str(e)
        print("An error occurred during processing:", process_log)

    return process_log

def print_summary_to_file(log, file_name, word_for_success, word_for_fail, test_name):
    has_to_write_out_the_log = False

    for line in log:
        if word_for_fail in line:
            has_to_write_out_the_log = True
        elif word_for_success in line:
            print(line)

    if has_to_write_out_the_log:
        with open(file_name, "w") as file:
            for line in log:
                file.write(line)

        print(f"{test_name} is faild. Please check the log file: {file_name}")


def main():
    parser = argparse.ArgumentParser(description="Program description.")
    parser.add_argument("--working-dir", required=False, help="Path to the working dir")
    parser.add_argument("--build-root", required=False, help="Path to the working dir")

    args = parser.parse_args()
    print(f"Argumentum: Working dir: {args.working_dir}")
    print(f"Argumentum: Build root: {args.build_root}")

    command_helper = ["python3", f"{args.working_dir}/tests/tests-u-runner/main.py", "--build-dir", f"{args.build_root}",
                      "--processes", "all", "--show-progress", "--force-generate"
                    ]

    # Run Parser tests
    parser_test_run_command = command_helper + ["--parser" ]

    parser_log = command_runner(parser_test_run_command, TestTypes.NORMAL)

    # Run Runtime tests
    runtime_test_run_command = command_helper + ["--ets-runtime", "--timeout", "60"]

    runtime_log = command_runner(runtime_test_run_command, TestTypes.NORMAL)

    # Functional tests
    functional_test_run_command = command_helper + ["--ets-func-tests"]

    functional_log = command_runner(functional_test_run_command, TestTypes.NORMAL)

    # Run Ets-cts test
    ets_cts_test_run_command =  command_helper + ["--ets-cts"]

    ets_cts_log = command_runner(ets_cts_test_run_command, TestTypes.NORMAL)

    # Run Clang-format
    clang_format_run_command = ["ninja", "-C", f"{args.build_root}", "code-style-check"]

    clang_format_log = command_runner(clang_format_run_command, TestTypes.CLANGFORMAT)

    # Run Clang-tidy
    clang_tidy_run_command = [f"{args.working_dir}/scripts/clang-tidy/clang_tidy_check.py", "--filename-filter=ets2panda",
                                    f"{args.working_dir}",  f"{args.build_root}"
                            ]

    clang_tidy_log = command_runner(clang_tidy_run_command,TestTypes.CLANGTIDY)

    print("\n\nTest results: \n")

    print(f"\nParser test results:")
    print_summary(parser_log, ["New failures at", "Summary("])

    print(f"\nRuntime test results:")
    print_summary(runtime_log, ["New failures at", "Summary("])

    print(f"\nFunctional test results:")
    print_summary(functional_log, ["Summary("])

    print(f"\nEts-cts test results:")
    print_summary(ets_cts_log, ["New failures at", "Summary("])

    print(f"\nClang-format results:")
    print_summary_to_file(clang_format_log, "clang-format.log", "Clang-format was passed successfully!", "Failed:", "Clang-format")

    print(f"\nClang-tidy results:")
    print_summary(clang_tidy_log,["Clang-tidy was passed successfully!", "Failed:"], "Done clang-tidy:")


if __name__ == "__main__":
    start_time = time.perf_counter()
    main()
    end_time = time.perf_counter()
    print("Runtime: ", (end_time - start_time)/60, " minute" )
