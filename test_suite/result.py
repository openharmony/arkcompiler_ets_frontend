#!/usr/bin/env python3
# coding: utf-8

"""
Copyright (c) 2023 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Description: output test results
"""

import logging
import time

import options

class TestResult:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.time = 0.0


def print_test_result(test_result, test_tasks):
    logging.info("========================================")
    logging.info("Test finished. The result is as following:")
    logging.info("=====> Summary")
    logging.info("Total test number: %s, took time: %.3f s", len(test_tasks), test_result.time)
    logging.info("Passed test number: %s", len(test_result.passed))
    logging.info("Failed test number: %s", len(test_result.failed))

    logging.info("=====> Detail Information")
    logging.info("-----")
    idx = 1
    for task in test_tasks:
        logging.info("task index: %d", idx)
        idx = idx + 1
        logging.info("task name: %s", task.name)
        logging.info("task type: %s", task.type)
        # print full compile result
        logging.info("--full compilation result:")
        logging.info("debug: %s, abc_size(byte) %s, time(s) %s, error message: %s",
                     task.full_compilation_info.debug_info.result,
                     task.full_compilation_info.debug_info.abc_size,
                     task.full_compilation_info.debug_info.time,
                     task.full_compilation_info.debug_info.error_message)
        logging.info("release: %s, abc_size(byte) %s, time(s) %s, error message: %s",
                     task.full_compilation_info.release_info.result,
                     task.full_compilation_info.release_info.abc_size,
                     task.full_compilation_info.release_info.time,
                     task.full_compilation_info.debug_info.error_message)

        # print incremental compile result
        logging.info("--incremental compilation result:")
        for inc_task in task.incre_compilation_info.values():
            logging.info("incre test: %s", inc_task.name)
            logging.info("debug: %s, abc_size(byte) %s, time(s) %s, error message: %s",
                         inc_task.debug_info.result,
                         inc_task.debug_info.abc_size,
                         inc_task.debug_info.time,
                         inc_task.debug_info.error_message)
            logging.info("release: %s, abc_size(byte) %s, time(s) %s, error message: %s",
                          inc_task.release_info.result,
                          inc_task.release_info.abc_size,
                          inc_task.release_info.time,
                          inc_task.release_info.error_message)

        # print other tests result
        for name, task_info in task.other_tests.items():
            logging.info("--test name: %s", name)
            logging.info("result: %s, error message: %s",
                         task_info.result,
                         task_info.error_message)

        logging.info("-----")
        logging.info("========================================")


def is_full_compilation_passed(task_info):
    if not options.arguments.compile_mode in ['all', 'full']:
        return True, True

    passed_debug = True
    passed_release = True

    if options.arguments.hap_mode in ['all', 'release']:
        passed_release = task_info.release_info.result == options.TaskResult.passed
    if options.arguments.hap_mode == ['all', 'debug']:
        passed_debug = task_info.debug_info.result == options.TaskResult.passed

    return passed_debug and passed_release


def is_incremental_compilation_passed(task_info):
    if not options.arguments.compile_mode in ['all', 'incremental']:
        return True

    if len(task_info) == 0:
        return False

    passed_debug = True
    passed_release = True
    for inc_task in task_info.values():
        if options.arguments.hap_mode in ['all', 'release']:
            passed_release = passed_release and inc_task.release_info.result == options.TaskResult.passed
        if options.arguments.hap_mode == ['all', 'debug']:
            passed_debug = passed_debug and inc_task.debug_info.result == options.TaskResult.passed

    return passed_debug and passed_release


def is_task_passed(task):
    passed = True

    passed = passed and is_full_compilation_passed(task.full_compilation_info)
    passed = passed and is_incremental_compilation_passed(task.incre_compilation_info)
    for test in task.other_tests.values():
       passed = passed and (test.result == options.TaskResult.passed)

    return passed


def collect_result(test_result, test_tasks, start_time):
    for task in test_tasks:
        if not is_task_passed(task):
            test_result.failed.append(task)
        else:
            test_result.passed.append(task)

    end_time = time.time()
    test_result.time = round(end_time - start_time, 3)


def email_result(test_result):
    # TODO
    return


def process_test_result(test_tasks, start_time):
    test_result = TestResult()

    collect_result(test_result, test_tasks, start_time)
    print_test_result(test_result, test_tasks)

    # TODO: add baseline comparison
    # TODO: add write result to a file

    if options.arguments.email_result:
        email_result(test_result)
