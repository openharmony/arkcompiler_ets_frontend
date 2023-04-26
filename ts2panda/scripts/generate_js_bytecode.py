#!/usr/bin/env python3
# coding: utf-8

"""
Copyright (c) 2021 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Description: Generate javascript byte code
"""

import os
import subprocess
import platform
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--src-js',
                        help='js source file')
    parser.add_argument('--dst-file',
                        help='the converted target file')
    parser.add_argument("--node",
                        help='path to nodejs exetuable')
    parser.add_argument('--frontend-tool-path',
                        help='path to frontend conversion tool')
    parser.add_argument("--node-modules",
                        help='path to node-modules exetuable')
    parser.add_argument("--debug", action='store_true',
                        help='whether add debuginfo')
    parser.add_argument("--module", action='store_true',
                        help='whether is module')
    parser.add_argument("--commonjs", action='store_true',
                        help='whether is commonjs')
    parser.add_argument("--q", action='store_true',
                        help='whether is d.ts')
    parser.add_argument("--b", action='store_true',
                        help='enable builtin types recognition for .d.ts files')
    parser.add_argument("--functionSourceCode", action='store_true',
                        help='compile abc with function sourcecode info')
    parser.add_argument("--merge-abc", action='store_true',
                        help='compile as merge abc')
    parser.add_argument("--output-proto", action='store_true',
                        help='output protoBin file')
    parser.add_argument("--run-multi-file-tests", action='store_true',
                        help='run multi-file tests')
    parser.add_argument("--merge-abc-path",
                        help='path to merge_abc binary tool')
    parser.add_argument("--src-ts",
                        help='ts source files')
    arguments = parser.parse_args()
    return arguments


def set_env(input_arguments):
    jsoner_format = ":"
    if platform.system() == "Windows":
        jsoner_format = ";"
    os.environ["PATH"] = input_arguments.node + \
        jsoner_format + os.environ["PATH"]


def run_command(cmd, execution_path):
    print(" ".join(cmd) + " | execution_path: " + execution_path)
    proc = subprocess.Popen(cmd, cwd=execution_path)
    proc.wait()


def copy_ts_files(input_arguments, path):
    (output_path, name) = os.path.split(input_arguments.src_js)
    remove_cmd = ['rm', '-rf', output_path]
    run_command(remove_cmd, path)

    copy_cmd = ['cp', '-r', input_arguments.src_ts, output_path]
    run_command(copy_cmd, path)


def merge_abc(input_arguments, path):
    (output_path, abc_file) = os.path.split(input_arguments.dst_file)
    merge_abc_cmd = [input_arguments.merge_abc_path,
                     "--input",
                     output_path,
                     "--output",
                     abc_file,
                     "--outputFilePath",
                     output_path]
    run_command(merge_abc_cmd, path)


def gen_abc_info(input_arguments):

    set_env(input_arguments)
    frontend_tool_path = input_arguments.frontend_tool_path

    (path, name) = os.path.split(frontend_tool_path)

    if not os.path.exists(os.path.join(path, "node_modules")):
        if input_arguments.node_modules:
            cmd = ['cp', "-rf", input_arguments.node_modules, path]
            run_command(cmd, path)
        else:
            cmd = ['npm', 'install']
            run_command(cmd, path)

    if input_arguments.run_multi_file_tests:
        copy_ts_files(input_arguments, path)

    cmd = [os.path.join(input_arguments.node, "node"),
           '--expose-gc',
           os.path.join(name, 'src/index.js'),
           input_arguments.src_js,
           '-o', input_arguments.dst_file,
           '-t', '0']

    if input_arguments.debug:
        cmd.append('--debug')
    if input_arguments.module:
        cmd.append('-m')
    if input_arguments.commonjs:
        cmd.append('-c')
    if input_arguments.q:
        cmd.append('-q')
    if input_arguments.b:
        cmd.append('-b')
    if input_arguments.functionSourceCode:
        cmd.append('--function-sourcecode')
    if input_arguments.merge_abc:
        cmd.append('--merge-abc')
    if input_arguments.output_proto:
        cmd.append('--output-proto')
    run_command(cmd, path)

    if input_arguments.run_multi_file_tests:
        merge_abc(input_arguments, path)

if __name__ == '__main__':
    gen_abc_info(parse_args())
