#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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

from glob import glob
import argparse
import copy
import json
import os
import stat
import subprocess
import threading

TEST_ROOT = os.path.dirname(os.path.abspath(__file__))
TEST_CASES = 'test_cases'
D8_REPO = 'd8_tool'
D8_EXECUTABLE_PROGRAM_PATH = 'd8'
D8_REPO_URL = 'https://gitee.com/littleOneYuan/d8.git'
JAVA_TEST_FRAMEWORK = 'java_test_framework'
RUN_JAVA_SCRIPT = 'run_java.py'
DEX_SIZE_DATA = 'dex_size.dat'
SIZE_COMPARISON_REPORT = 'size_comparison_report.html'
HTML_CONTENT = \
"""
<!DOCTYPE html>
<html>
<head>
    <title>Size Comparison Report</title>
    <style>
        table {
            width: 50%;
            border-collapse: collapse;
            margin: auto;
        }
        th, td {
            padding: 8px;
            text-align: center;
            border: 1px solid black;
            white-space: nowrap;
        }
        td:nth-child(2) {
            text-align: left;
        }
        h1 {
            text-align: center;
        }
    </style>
</head>
<body>
    <h1>Size Comparison Report</h1>
    <table>
        <tr>
            <th>No</th>
            <th>Case Name</th>
            <th>JS Case - ABC Size</th>
            <th>TS Case - ABC Size</th>
            <th>Java Case - DEX Size</th>
        </tr>
"""


def is_file(parser, arg):
    if not os.path.isfile(arg):
        parser.error("The file '%s' does not exist" % arg)
    return os.path.abspath(arg)


def check_timeout(value):
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("%s is an invalid timeout value" % value)
    return ivalue


def get_args():
    description = "Generate bytecode file size statistics for js-ts-java benchmarking test cases."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--es2abc-path', dest='es2abc_path', type=lambda arg : is_file(parser, arg),
                        help='Path to the executable program es2abc', required=True)
    parser.add_argument('--javac-path', dest='javac_path', type=lambda arg : is_file(parser, arg),
                        help='Path to javac compiler', required=True)
    parser.add_argument('--d8-path', dest='d8_path', type=lambda arg : is_file(parser, arg),
                        help='Path to the executable program d8')
    parser.add_argument('--timeout', type=check_timeout, dest='timeout', default=180, 
                        help='Time limits for use case execution (In seconds)')
    return parser.parse_args()


def check_d8(args):
    if args.d8_path:
        return True
    d8_path = pull_repo(D8_REPO_URL, D8_REPO)
    if d8_path:
        args.d8_path = os.path.join(d8_path, D8_EXECUTABLE_PROGRAM_PATH)
        return True
    return False


def generate_size_comparison_report(js_output, ts_output, java_output):
    global HTML_CONTENT
    report_path = os.path.join(TEST_ROOT, SIZE_COMPARISON_REPORT)
    longest_output = max(js_output, ts_output, java_output, key=len)

    for case_number, case_path in enumerate(longest_output.keys(), 1):
        HTML_CONTENT = ''.join([HTML_CONTENT, f"""
        <tr>
            <td>{case_number}</td>
            <td>{case_path}</td>
            <td>{js_output.get(case_path, 'N/A')}</td>
            <td>{ts_output.get(case_path, 'N/A')}</td>
            <td>{java_output.get(case_path, 'N/A')}</td>
        </tr>
        """])

    HTML_CONTENT = ''.join([HTML_CONTENT, "</table></body></html>"])

    flags = os.O_RDWR | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(report_path, flags, mode), 'w') as report:
        report.truncate()
        report.write(HTML_CONTENT)


def get_case_name(case_path):
    filename = case_path.split('/')[-1]
    case_name = filename[:filename.rfind('.')]
    return case_name


def git_clone(git_url, code_dir, pull=False):
    cur_dir = os.getcwd()
    cmd = ['git', 'clone', git_url, code_dir]
    if pull:
        os.chdir(code_dir)
        cmd = ['git', 'pull']
    process = subprocess.Popen(cmd)
    process.wait()
    os.chdir(cur_dir)
    result = True
    if process.returncode:
        print(f"\n[ERROR]: git clone or pull '{git_url}' Failed!")
        result = False
    return result


def pull_repo(case_url, dir):
    dir_path = os.path.join(TEST_ROOT, dir)
    pull = False
    if os.path.exists(dir_path):
        pull = True
    clone_result = git_clone(case_url, dir_path, pull)
    if not clone_result:
        return ''
    return dir_path


class ES2ABCRunner:
    def __init__(self, args):
        self.args = args
        self.cmd = [args.es2abc_path]
        self.case_list = []
        self.output = {}

    def add_flags(self, flags:list):
        self.cmd.extend(flags)

    def add_case(self, case_path, extension):
        if not os.path.isabs(case_path):
            case_path = os.path.join(TEST_ROOT, case_path)
        abs_case_path = os.path.abspath(case_path)
        if abs_case_path not in self.case_list and abs_case_path.endswith(extension):
            self.case_list.append(case_path)

    def add_directory(self, directory, extension):
        if not os.path.isabs(directory):
            directory = os.path.join(TEST_ROOT, directory)
        glob_expression = os.path.join(os.path.abspath(directory), "**/*%s" % (extension))
        cases = glob(glob_expression, recursive=True)
        for case in cases:
            self.add_case(case, extension)

    def run(self):
        self.case_list.sort()
        for file_path in self.case_list:
            abc_file_path = ''.join([file_path[:file_path.rfind('.')], '.abc'])
            cmd = copy.deepcopy(self.cmd)
            cmd.extend([f'--output={abc_file_path}'])
            cmd.extend([file_path])
            try:
                subprocess.run(cmd, timeout=self.args.timeout)
            except subprocess.TimeoutExpired:
                print(f'[WARNING]: Timeout! {file_path}')
            except Exception as e:
                print(f"[ERROR]: {e}")

            abc_file_size = 0
            if os.path.exists(abc_file_path):
                abc_file_size = os.path.getsize(abc_file_path)
                os.remove(abc_file_path)
            self.output[get_case_name(file_path)] = abc_file_size
            print(f'[INFO]: FINISH: {file_path}!')


class JavaD8Runner:
    def __init__(self, args):
        self.args = args
        self.java_test_root = os.path.join(TEST_ROOT, TEST_CASES, JAVA_TEST_FRAMEWORK)
        self.run_java = os.path.join(self.java_test_root, RUN_JAVA_SCRIPT)
        self.output = {}

    def get_output_from_file(self):
        dex_size_data = os.path.join(self.java_test_root, DEX_SIZE_DATA)
        flags = os.O_RDONLY
        mode = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(dex_size_data, flags, mode), 'r') as f:
            self.output = json.load(f)
        if os.path.exists(dex_size_data):
            os.remove(dex_size_data)

    def run(self):
        if self.java_test_root:
            cmd = [self.run_java, '--javac-path', self.args.javac_path, '--d8-path', self.args.d8_path]
            if self.args.timeout:
                cmd.extend(['--timeout', str(self.args.timeout)])
            try:
                subprocess.run(cmd)
                self.get_output_from_file()
            except subprocess.CalledProcessError as e:
                print(f'[ERROR]: Execute run_java Failed! Return Code: {e.returncode}')
            except Exception as e:
                print(f"[ERROR]: {e}")


def main():
    args = get_args()
    if not check_d8(args):
        print('[ERROR]: check d8 Failed!')
        return

    js_runner = ES2ABCRunner(args)
    ts_runner = ES2ABCRunner(args)
    java_runner = JavaD8Runner(args)

    # add flags
    js_runner.add_flags(['--module'])
    ts_runner.add_flags(['--module'])

    # add cases
    js_runner.add_directory(TEST_CASES, '.js')
    ts_runner.add_directory(TEST_CASES, '.ts')

    js_thread = threading.Thread(target=js_runner.run)
    ts_thread = threading.Thread(target=ts_runner.run)
    java_thread = threading.Thread(target=java_runner.run)

    js_thread.start()
    ts_thread.start()
    java_thread.start()
    js_thread.join()
    ts_thread.join()
    java_thread.join()

    generate_size_comparison_report(js_runner.output, ts_runner.output, java_runner.output)


if __name__ == "__main__":
    main()