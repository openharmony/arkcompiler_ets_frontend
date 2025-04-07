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
    stdout, stderr = proc.communicate(timeout=600)
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


def find_files_by_prefix_suffix(directory, prefix, suffix):
    matched_files = []
    for filename in os.listdir(directory):
        if filename.startswith(prefix) and filename.endswith(suffix):
            matched_files.append(os.path.join(directory, filename))
    return sorted(matched_files, key=os.path.getctime, reverse=True)


def clean_old_packages(directory, prefix, suffix):
    res = True
    matched_files = find_files_by_prefix_suffix(directory, prefix, suffix)
    if (matched_files):
        for file in matched_files:
            try:
                os.remove(file)
            except Exception:
                res = False
    return res


def pack_arkanalyzer(options):
    aa_path = os.path.join(options.source_path, 'arkanalyzer')
    pack_prefix = 'arkanalyzer-'
    pack_suffix = '.tgz'
    clean_old_packages(aa_path, pack_prefix, pack_suffix)

    ts_install_cmd = [options.npm, 'install', options.typescript]
    compile_cmd = [options.npm, 'run', 'compile']
    pack_cmd = [options.npm, 'pack']
    run_cmd(ts_install_cmd, aa_path)
    run_cmd(compile_cmd, aa_path)
    run_cmd(pack_cmd, aa_path)


def install_homecheck(options):
    pack_arkanalyzer(options)
    aa_path = os.path.join(options.source_path, 'arkanalyzer')
    hc_path = os.path.join(options.source_path, 'homecheck')
    aa_pack_prefix = 'arkanalyzer-'
    hc_pack_prefix = 'homecheck-'
    pack_suffix = '.tgz'
    exist_aa_packs = find_files_by_prefix_suffix(aa_path, aa_pack_prefix, pack_suffix)
    if (exist_aa_packs):
        aa_install_cmd = [options.npm, 'install', exist_aa_packs[0]]
        run_cmd(aa_install_cmd, hc_path)
    else:
        raise Exception('Failed to find arkanalyzer npm package')

    clean_old_packages(hc_path, hc_pack_prefix, pack_suffix)
    ts_install_cmd = [options.npm, 'install', '--no-save', options.typescript]
    pack_cmd = [options.npm, 'pack']
    compile_cmd = [options.npm, 'run', 'compile']
    run_cmd(ts_install_cmd, hc_path)
    run_cmd(compile_cmd, hc_path)
    run_cmd(pack_cmd, hc_path)
    exist_hc_packs = find_files_by_prefix_suffix(hc_path, hc_pack_prefix, pack_suffix)
    if (exist_hc_packs):
        hc_install_cmd = [options.npm, 'install', exist_hc_packs[0]]
        run_cmd(hc_install_cmd, options.source_path)
    else:
        raise Exception('Failed to find homecheck npm package')


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
    install_homecheck(options)
    install_typescript(options)
    node_modules_path = os.path.join(options.source_path, "node_modules")
    extract(options.typescript, node_modules_path, "typescript")
    build(options)
    copy_output(options)


if __name__ == '__main__':
    sys.exit(main())


