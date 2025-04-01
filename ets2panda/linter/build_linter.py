#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2025 Huawei Device Co., Ltd.
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

import argparse
import os
import shutil
import subprocess
import sys
import tarfile


def copy_files(source_path, dest_path, is_file=False):
    try:
        if is_file:
            if not os.path.exists(os.path.dirname(dest_path)):
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy(source_path, dest_path)
        else:
            shutil.copytree(source_path, dest_path, dirs_exist_ok=True,
                symlinks=True)
    except Exception as err:
        raise Exception("Copy files failed. Error: " + str(err)) from err


def run_cmd(cmd, execution_path=None):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           cwd=execution_path)
    stdout, stderr = proc.communicate(timeout=300)
    if proc.returncode != 0:
        raise Exception(stderr.decode())


def build(options):
    build_cmd = [options.npm, 'run', 'build']
    pack_cmd = [options.npm, 'pack']
    run_cmd(build_cmd, options.source_path)
    run_cmd(pack_cmd, options.source_path)


def copy_output(options):
    run_cmd(['rm', '-rf', options.output_path])
    src = os.path.join(options.source_path, 'panda-tslinter-{}.tgz'.format(options.version))
    dest = os.path.join(options.output_path, 'panda-tslinter-{}.tgz'.format(options.version))
    copy_files(src, dest, True)
    try:
        with tarfile.open(dest, 'r:gz') as tar:
            tar.extractall(path=options.output_path)
    except tarfile.TarError as e:
        raise Exception("Error extracting files") from e
    copy_files(os.path.join(options.output_path, 'package'), options.output_path)
    run_cmd(['rm', '-rf', os.path.join(options.output_path, 'package')])
    run_cmd(['rm', '-rf', dest])
    src = os.path.join(options.source_path, 'tsconfig.json')
    dest = os.path.join(options.output_path, 'tsconfig.json')
    copy_files(src, dest, True)


def install_typescript(options):
    cmd = [options.npm, 'install', '--no-save', options.typescript]
    run_cmd(cmd, options.source_path)


def extract(package_path, dest_path, package_name):
    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            tar.extractall(path=dest_path)
    except tarfile.TarError as e:
        raise Exception("Error extracting files") from e
    dest_package_path = os.path.join(dest_path, package_name)
    if (os.path.exists(dest_package_path)):
        shutil.rmtree(dest_package_path)
    os.rename(os.path.join(dest_path, 'package'), dest_package_path)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--npm', help='path to a npm exetuable')
    parser.add_argument('--source-path', help='path to build system source')
    parser.add_argument('--output-path', help='path to output')
    parser.add_argument('--typescript', help='path to typescript')
    parser.add_argument('--version', help='linter version')

    options = parser.parse_args()
    return options


def main():
    options = parse_args()
    install_typescript(options)
    node_modules_path = os.path.join(options.source_path, "node_modules")
    extract(options.typescript, node_modules_path, "typescript")
    build(options)
    copy_output(options)


if __name__ == '__main__':
    sys.exit(main())


