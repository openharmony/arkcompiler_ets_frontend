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
import pandas
import smtplib
import time
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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


def email_result(test_result, test_tasks):
    sender = ''
    password = ''
    receiver = []
    subject = 'SDK Test Daily Report'

    msg = MIMEMultipart()
    msg['From'] = 'wuhailong'
    msg['To'] = ", ".join(receiver)
    msg['Subject'] = Header(subject, 'utf-8')

    summary_data = {
        'Total test number': [len(test_tasks)],
        'Took time (s)': [test_result.time],
        'Passed test number': [len(test_result.passed)],
        'Failed test number': [len(test_result.failed)]
    }

    detail_data = []
    idx = 1
    for task in test_tasks:
        task_data = {
            'Task index': idx,
            'Task name': task.name,
            'Task type': task.type
        }
        
        full_compilation_debug = task.full_compilation_info.debug_info
        full_compilation_release = task.full_compilation_info.release_info
        task_data['Full Compilation - Debug'] = {
            'Result': full_compilation_debug.result,
            'ABC Size': full_compilation_debug.abc_size,
            'Error Message': full_compilation_debug.error_message
        }
        task_data['Full Compilation - Release'] = {
            'Result': full_compilation_release.result,
            'ABC Size': full_compilation_release.abc_size,
            'Error Message': full_compilation_release.error_message
        }
        
        incremental_compilation = task.incre_compilation_info
        for inc_task_name, inc_task_info in incremental_compilation.items():
            inc_task_debug = inc_task_info.debug_info
            inc_task_release = inc_task_info.release_info
            task_data[f'Incremental Compilation - {inc_task_name} - Debug'] = {
                'Result': inc_task_debug.result,
                'ABC Size': inc_task_debug.abc_size,
                'Error Message': inc_task_debug.error_message
            }
            task_data[f'Incremental Compilation - {inc_task_name} - Release'] = {
                'Result': inc_task_release.result,
                'ABC Size': inc_task_release.abc_size,
                'Error Message': inc_task_release.error_message
            }
        
        for other_test_name, other_test_info in task.other_tests.items():
            task_data[f'Other Test - {other_test_name}'] = {
                'Result': other_test_info.result,
                'Error Message': other_test_info.error_message
            }
        
        detail_data.append(task_data)
    
    summary_df = pandas.DataFrame(summary_data)
    detail_df = pandas.DataFrame(detail_data)

    detail_table = '<table>'
    detail_table += '<tr>'
    for column in detail_df.columns:
        detail_table += f'<th>{column}</th>'
    detail_table += '</tr>'
    for _, row in detail_df.iterrows():
        detail_table += '<tr>'
        for column, value in row.items():
            if isinstance(value, dict):
                detail_table += '<td>'
                detail_table += '<table>'
                for sub_column, sub_value in value.items():
                    detail_table += f'<tr><td>{sub_column}</td><td>{sub_value}</td></tr>'
                detail_table += '</table>'
                detail_table += '</td>'
            elif isinstance(value, list):
                detail_table += '<td>'
                detail_table += '<table>'
                for sub_value in value:
                    detail_table += f'<tr><td>{sub_value}</td></tr>'
                detail_table += '</table>'
                detail_table += '</td>'
            else:
                detail_table += f'<td>{value}</td>'
        detail_table += '</tr>'
    detail_table += '</table>'

    summary_table = MIMEText(summary_df.to_html(index=False), 'html')
    msg.attach(summary_table)

    html_content = f'''
    <html>
    <head>
    <style>
    body {{
        font-family: Arial, sans-serif;
        margin: 20px;
    }}

    h2 {{
        color: #333;
    }}

    table {{
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 20px;
    }}

    table th, table td {{
        padding: 8px;
        border: 1px solid #ddd;
    }}

    table th {{
        background-color: #f2f2f2;
        font-weight: bold;
    }}

    .sub-table {{
        border-collapse: collapse;
        width: 100%;
    }}

    .sub-table td {{
        padding: 4px;
        border: 1px solid #ddd;
    }}
    </style>
    </head>
    <body>
    <h2>Summary</h2>
    {summary_table}
    <h2>Detail Information</h2>
    {detail_table}
    </body>
    </html>
    '''

    today_date = time.strftime("%Y%m%d")
    daily_report_file=f'SDK-test-report-{today_date}.html'
    with open(daily_report_file, 'w') as report:
        report.write(html_content)

    with open(daily_report_file, 'rb') as mesg:
        attach_txt = MIMEApplication(mesg.read())
        attach_txt.add_header('Content-Disposition', 'attachment', filename = daily_report_file)
        msg.attach(attach_txt)

    logging.info('Sending email')
    smtp_server = 'smtp.163.com'
    smtp = smtplib.SMTP(smtp_server, 25)
    smtp.login(sender, password)
    smtp.sendmail(sender, receiver, msg.as_string())
    smtp.quit()
    logging.info('Sent email successfully!')


def process_test_result(test_tasks, start_time):
    test_result = TestResult()

    collect_result(test_result, test_tasks, start_time)
    print_test_result(test_result, test_tasks)

    # TODO: add baseline comparison
    # TODO: add write result to a file

    if options.arguments.email_result:
        email_result(test_result, test_tasks)
