#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

import argparse
import os
import subprocess
import sys
from pathlib import Path


def parse_options():
    # panda root default
    panda_env = os.environ.get('PANDA_ROOT')
    arkdir_default = panda_env if panda_env else os.path.join(Path.home(), 'panda')

    # panda build dir
    panda_binary_env = os.environ.get('PANDA_BINARY_ROOT')
    builddir_default = panda_binary_env if panda_binary_env else os.path.join(Path.home(), 'panda', 'build')

    parser = argparse.ArgumentParser(epilog='Run the selected benchmark with Ark')
    parser.add_argument('--arkdir', metavar='DIR', default=arkdir_default,
                          help='specify ark directory (default: %(default)s)')
    parser.add_argument('--builddir', metavar='DIR', default=builddir_default,
                          help='specify ark directory (default: %(default)s)')
    parser.add_argument('--timeout', metavar='SEC', type=int, default=60, help='timeout (default: %(default)s)')
    parser.add_argument('-rt', '--runtime', action='store_true', dest='runtime', help='Runtime tests')
    parser.add_argument('-r', '--regression', action='store_true', dest='regression', help='Regression tests')
    parser.add_argument('-cts', '--cts', action='store_true', dest='cts', help='CTS tests')
    parser.add_argument('-f', '--func', action='store_true', dest='functional', help='Functional tests')
    parser.add_argument('-t', '--test262', action='store_true', dest='test262', help='Test262 tests')
    parser.add_argument('--all', action='store_true', dest='all', help='Run the listed benchmarks')

    return parser.parse_args()


def main():
    options = parse_options()

    if not os.path.exists(options.arkdir):
        print("The following ark directory does not exist: {0}".format(options.arkdir))
        sys.exit(1)

    if not os.path.exists(options.builddir):
        print("The following build directory does not exist: {0}".format(options.builddir))
        sys.exit(1)

    testrunner = os.path.join(options.arkdir, 'tests', 'tests-u-runner', 'main.py')

    if not os.path.isfile(testrunner):
        print("The following script is not executable or exist: {0}".format(testrunner))

    general_cmd = [
        'python', testrunner, '--build-dir', options.builddir, '--force-generate',
        '--show-progress', '--processes', 'all', '--timeout', str(options.timeout)
    ]

    if options.all:
        options.regression = options.runtime = options.cts = options.functional = options.test262 = True

    if options.regression:
        res = subprocess.call(general_cmd + ['--parser'])
    if options.runtime:
        res = subprocess.call(general_cmd + ['--ets-runtime'])
    if options.functional:
        res = subprocess.call(general_cmd + ['--ets-func-tests'])
    if options.test262:
        res = subprocess.call(general_cmd + ['--test262'])
    if options.cts:
        res = subprocess.call(general_cmd + ['--ets-cts'])


if __name__ == '__main__':
    main()
