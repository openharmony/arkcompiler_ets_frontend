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

Description: process options and configs for test suite
"""

import argparse
import logging
import os
import yaml

from enum import Enum
from utils import init_logger

YAML_PATH = './config.yaml'

class TaskResult(Enum):
    undefind = 0
    passed = 1
    failed = 2


class CompilationInfo:
    def __init__(self):
        self.result = TaskResult.undefind
        self.error_message = ''
        self.time = 0
        self.abc_size = 0


class FullCompilationInfo:
    def __init__(self):
        self.debug_info = CompilationInfo()
        self.release_info = CompilationInfo()


class IncCompilationInfo:
    def __init__(self):
        self.debug_info = CompilationInfo()
        self.release_info = CompilationInfo()
        self.name = ''


class BackupInfo:
    def __init__(self):
        self.cache_path = ''
        self.cache_debug = ''
        self.cache_release = ''
        self.output_debug = []
        self.output_release = []


class TestTask:
    def __init__(self):
        self.name = ''
        self.path = ''
        self.type = ''
        self.build_path = []
        self.output_hap_path = ''
        self.output_app_path = ''
        self.inc_modify_file = []

        self.full_compilation_info = FullCompilationInfo()
        self.incre_compilation_info = {}
        self.break_compilation_info = CompilationInfo()
        self.abc_consistency = TaskResult.undefind

        self.backup_info = BackupInfo()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdkPath', type=str, dest='sdk_path', default='',
                        help='specify sdk path if need to update sdk')
    parser.add_argument('--buildMode', type=str, dest='build_mode', default='all',
                        choices=['all', 'assemble', 'preview', 'hotreload', 'hotfix'],
                        help='specify build mode')
    parser.add_argument('--hapMode', type=str, dest='hap_mode', default='all',
                        choices=['all', 'debug', 'release'],
                        help='specify hap mode')
    parser.add_argument('--compileMode', type=str, dest='compile_mode', default='all',
                        choices=['all', 'full', 'incremental'],
                        help='specify compile mode')
    parser.add_argument('--testCase', type=str, dest='test_case', default='all',
                        choices=['all', 'fa', 'stage', 'compatible8', 'js'],
                        help='specify test cases')
    parser.add_argument('--testHap', type=str, dest='test_hap', default='all',
                        help="specify test haps, option can be 'all' or a list of haps seperated by ','")
    parser.add_argument('--imagePath', type=str, dest='image_path', default='all',
                        help='specify image path if need to update rk/phone images')
    parser.add_argument('--packOnly', type=bool, dest='pack_only', default=True,
                        help='specify how to verify. if packOnly is true, will not verify results by running haps')
    parser.add_argument('--outputBinarySize', type=bool, dest='output_binary_size', default=True,
                        help='specify whether to output binary size to the result')
    parser.add_argument('--outputCompileTime', type=bool, dest='output_compile_time', default=True,
                        help='specify whether to output compilation time to the result')
    parser.add_argument('--emailResult', type=bool, dest='email_result', default=True,
                        help='specify whether to send result by email')
    parser.add_argument('--resultFile', type=str, dest='result_file', default='',
                        help='specify whether to output results to a file')
    parser.add_argument('--logLevel', type=str, dest='log_level', default='error',
                        choices=['debug', 'info', 'warn', 'error'],
                        help='specify log level of test suite')
    parser.add_argument('--logFile', type=str, dest='log_file', default='',
                        help='specify the file log outputs to, empty string will output to console')
    parser.add_argument('--compileTimeout', type=int, dest='compile_timeout', default=600,
                        help='specify deveco compilation timeout')
    global arguments
    arguments = parser.parse_args()


def parse_configs():
    with open(YAML_PATH, 'r') as config_file:
        global configs
        configs = yaml.safe_load(config_file)


def create_test_tasks():
    task_list = []
    haps_list = configs['haps']
    test_cases = 'all' if arguments.test_case == 'all' else []
    test_haps = 'all' if arguments.test_hap == 'all' else []
    if test_cases != 'all':
        test_cases = arguments.test_case.split(',')
    if test_haps != 'all':
        test_haps = arguments.test_hap.split(',')

    for hap in haps_list:
        if test_cases == 'all' or test_haps == 'all' \
           or (test_cases and (hap['type'] in test_cases)) \
           or (test_haps and (hap['name'] in test_haps)):
            if not os.path.exists(hap['path']):
                logging.warn("Path of hap %s dosen't exist: %s" % (hap['name'], hap['path']))
                continue
            task = TestTask()
            task.name = hap['name']
            task.path = hap['path']
            task.type = hap['type']
            task.build_path = hap['build_path']
            task.output_hap_path = hap['output_hap_path']
            task.output_app_path = hap['output_app_path']
            task.inc_modify_file = hap['inc_modify_file']
            task.backup_info.cache_path = os.path.join(task.path, 'test_suite_cache')

            task_list.append(task)

    return task_list


def process_options():
    parse_args()
    init_logger(arguments.log_level, arguments.log_file)
    parse_configs()
    return create_test_tasks()