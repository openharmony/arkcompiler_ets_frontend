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

import copy
import logging
import os
import time

import pandas

import options


incremetal_compile_tests = ["no_change",
                            "add_oneline",
                            "add_file",
                            "delete_file",
                            "reverse_hap_mode",
                            "change_module_name"
                            ]

other_tests = ["binary_consistency",
               "break_continue_compile",
               "compile_with_error",
               "compile_with_exceed_length",
               "ohos_test"
               ]


class TestResult:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.time = 0.0


def print_result(test_result, test_tasks):
    logging.info("========================================")
    logging.info("Test finished. The result is as following:")
    logging.info("=====> Summary")
    logging.info("Total test number: %s, took time: %.3f s",
                 len(test_tasks), test_result.time)
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
        return True

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
    passed = is_full_compilation_passed(task.full_compilation_info) and \
        is_incremental_compilation_passed(task.incre_compilation_info)

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


def get_result_symbol(result_type):
    if result_type == options.TaskResult.passed:
        return '√'
    elif result_type == options.TaskResult.failed:
        return '×'
    else:
        return '-'


def generate_summary_data(test_result, test_tasks):
    # collect summary data
    passed_task_name_list = []
    for task in test_result.passed:
        passed_task_name_list.append(task.name)
    failed_task_name_list = []
    for task in test_result.failed:
        failed_task_name_list.append(task.name)

    summary_data = {
        'Total Test Number': len(test_tasks),
        'Passed Test Number': len(test_result.passed),
        'Failed Test Number': len(test_result.failed),
        'Passed Tests': ','.join(passed_task_name_list),
        'Failed Tests': ','.join(failed_task_name_list),
        'Test Took Time(s)': test_result.time
    }

    return summary_data


def generate_detail_data(test_tasks):
    time_size_data = []
    result_data = []

    idx = 0
    for task in test_tasks:
        idx += 1
        task_time_size_data = {
            'Task Index': idx,
            'Task Name': task.name
        }
        task_result_data = copy.deepcopy(task_time_size_data)
        task_result_data['Task Type'] = ','.join(task.type)

        full_compilation_debug = task.full_compilation_info.debug_info
        full_compilation_release = task.full_compilation_info.release_info
        task_time_size_data[
            '[Full Compilation]\n[Debug]\n[Compilation Time(s)]'] = full_compilation_debug.time
        task_time_size_data[
            '[Full Compilation]\n[Release]\n[Compilation Time(s)]'] = full_compilation_release.time
        task_result_data['[Debug]'] = get_result_symbol(
            full_compilation_debug.result)
        task_result_data['[Release]'] = get_result_symbol(
            full_compilation_release.result)

        for test in incremetal_compile_tests:
            debug_result = options.TaskResult.undefind
            release_result = options.TaskResult.undefind
            if test in task.incre_compilation_info.keys():
                inc_task_info = task.incre_compilation_info[test]
                debug_result = inc_task_info.debug_info.result
                release_result = inc_task_info.release_info.result
            task_result_data[f'[Debug]\n{test}'] = get_result_symbol(
                debug_result)
            task_result_data[f'[Release]\n{test}'] = get_result_symbol(
                release_result)

            if test == 'add_oneline':
                debug_test_time = 0
                release_test_time = 0
                if test in task.incre_compilation_info.keys():
                    inc_task_info = task.incre_compilation_info[test]
                    debug_test_time = inc_task_info.debug_info.time
                    release_test_time = inc_task_info.release_info.time

                task_time_size_data[
                    '[Incremental Compilation]\n[Debug]\n[Compilation Time(s)]'] = debug_test_time
                task_time_size_data[
                    '[Incremental Compilation]\n[Release]\n[Compilation Time(s)]'] = release_test_time

        for test in other_tests:
            result = options.TaskResult.undefind
            if test in task.other_tests.keys():
                task_info = task.other_tests[test]
                result = task_info.result
            task_result_data[f'{test}'] = get_result_symbol(result)

        task_time_size_data['[Abc Size(byte)]\n[Debug]'] = full_compilation_debug.abc_size
        task_time_size_data['[Abc Size(byte)]\n[Release]'] = full_compilation_release.abc_size
        time_size_data.append(task_time_size_data)
        result_data.append(task_result_data)

    detail_data = {
        'result_data': result_data,
        'time_size_data': time_size_data
    }
    return detail_data


def generate_data_html(summary_data, detail_data):
    # summary table
    key_value_pairs = [
        f'<tr><td>{key}</td><td>{value}</td></tr>' for key, value in summary_data.items()]
    summary_table_content = ''.join(key_value_pairs)
    summary_table = f'<table id=sdk>{summary_table_content}</table>'

    # time and size table
    time_size_data = detail_data.get('time_size_data')
    time_size_df = pandas.DataFrame(time_size_data)

    time_size_table_header = '<tr>' + \
        ''.join(
            [f'<th rowspan="2">{column}</th>' for column in time_size_df.columns[:2]])
    time_size_table_header += '<th colspan="2">Full Compilation Time(s)</th>' + \
        f'<th colspan="2">Incremental Compilation Time(s)</th>' + \
        f'<th colspan="2">Abc Size(byte)</th></tr>'
    time_size_table_sub_header = '<tr>' + \
        f'<th>[Debug]</th><th>[Release]</th>' * 3 + '</tr>'

    time_size_table_content = ''.join([
        '<tr>' + ''.join([f'<td>{value}</td>' for _,
                         value in row.items()]) + '</tr>'
        for _, row in time_size_df.iterrows()
    ])
    time_size_table = f'<table id=sdk> \
        {time_size_table_header}{time_size_table_sub_header}{time_size_table_content}</table>'

    # result table
    result_data = detail_data.get('result_data')
    result_df = pandas.DataFrame(result_data)

    result_table_header = '<tr>' + \
        ''.join(
            [f'<th rowspan="2">{column}</th>' for column in result_df.columns[:3]])
    result_table_header += '<th colspan="2">Full Compilation</th>' + \
        f'<th colspan={len(incremetal_compile_tests) * 2}>Incremental Compilation</th>' + \
        f'<th colspan={len(other_tests)}>Other Tests</th></tr>'

    result_table_sub_header = '<tr>' + \
        ''.join(
            [f'<th>{column}</th>' for column in result_df.columns[3:]]) + '</tr>'
    result_table_content = ''.join([
        '<tr>' + ''.join([f'<td>{value}</td>' for _,
                         value in row.items()]) + '</tr>'
        for _, row in result_df.iterrows()
    ])
    result_table = f'<table id=sdk> \
        {result_table_header}{result_table_sub_header}{result_table_content}</table>'

    return summary_table, time_size_table, result_table


def generate_report_html(summary_data, detail_data):
    [summary_table, time_size_table, result_table] = generate_data_html(
        summary_data, detail_data)

    html_content = f'''
    <html>
    <head>
    <style>
    #sdk body {{
        font-family: Arial, sans-serif;
        margin: 20px;
    }}
    #sdk h2 {{
        color: #333;
    }}
    #sdk {{
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 20px;
    }}
    #sdk th, #sdk td {{
        padding: 8px;
        border: 1px solid #ddd;
    }}
    #sdk th {{
        background-color: #f2f2f2;
        font-weight: bold;
    }}
    #sdk tr:nth-child(odd) {{
        background-color: #f9f9f9;
    }}
    </style>
    </head>

    <body>
    <h2>SDK Test Results</h2>
    <h3>Summary</h3>
    {summary_table}
    <h3>Detail Information</h3>
    <h4>Test Result</h4>
    {result_table}
    <h4>Compilation Time And Abc Size</h4>
    {time_size_table}
    <p>
    Notes:<br>
    1. Incremental compilation time refers to add-one line incremental compile.<br>
    2. For details compile output or error message during compile, please refer to attachment of log file.<br>
    3. For sdk commit tags, please refer to attachment of manifest file(to be added).
    </p>
    </body>
    </html>
    '''

    daily_report_file = options.configs.get('output_html_file')
    with open(daily_report_file, 'w', encoding='utf-8') as report:
        report.write(html_content)


def generate_log_file():
    logger = logging.getLogger()
    if not hasattr(logger.handlers[0], 'baseFilename'):
        return
    log_file = logger.handlers[0].baseFilename
    logger.handlers[0].close()
    output_log_file = options.configs.get('log_file')
    os.rename(log_file, output_log_file)


def generate_result_reports(test_result, test_tasks):
    summary_data = generate_summary_data(test_result, test_tasks)
    detail_data = generate_detail_data(test_tasks)
    generate_report_html(summary_data, detail_data)
    generate_log_file()


def process_test_result(test_tasks, start_time):
    test_result = TestResult()

    collect_result(test_result, test_tasks, start_time)
    print_result(test_result, test_tasks)
    generate_result_reports(test_result, test_tasks)
