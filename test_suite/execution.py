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

Description: execute test tasks
"""

import logging
import os
import re
import subprocess
import shutil
import zipfile

import options
import utils


def validate_output_for_jsbundle(info, uncompressed_output_path, is_debug):
    abc_files = []
    for root, dirs, files in os.walk(uncompressed_output_path):
        for file in files:
            if file.endswith('.abc'):
                abc_files.append(os.path.join(root, file))

    total_size = 0
    for file in abc_files:
        total_size += os.path.getsize(os.path.join(uncompressed_output_path, file))
    if total_size == 0:
        info.result = options.TaskResult.failed
        info.error_message = "abc not found or abc size is 0"
        return False
    else:
        info.abc_size = total_size

    if is_debug:
        for file in abc_files:
            sourcemap_file = file.replace('.abc', '.js.map')
            if not os.path.exists(os.path.join(uncompressed_output_path, sourcemap_file)):
                info.result = options.TaskResult.failed
                info.error_message = "sourcemap not found"
                return False

    return True


def validate_output_for_esmodule(info, task_type, uncompressed_output_path, is_debug):
    abc_sourcemap_path = os.path.join(uncompressed_output_path, 'ets')

    modules_abc_path = os.path.join(abc_sourcemap_path, 'modules.abc')
    if not os.path.exists(modules_abc_path):
        info.result = options.TaskResult.failed
        info.error_message = "modules.abc not found"
        return False

    modules_abc_size = os.path.getsize(modules_abc_path)
    if modules_abc_size <= 0:
        info.result = options.TaskResult.failed
        info.error_message = "modules.abc size is 0"
        return False
    info.abc_size = modules_abc_size

    if task_type == 'stage_widget':
        widget_abc_path = os.path.join(abc_sourcemap_path, 'widgets.abc')
        if not os.path.exists(widget_abc_path):
            info.result = options.TaskResult.failed
            info.error_message = "widgets.abc not found"
            return False

        widgets_abc_size = os.path.getsize(widget_abc_path)
        if widgets_abc_size <= 0:
            info.result = options.TaskResult.failed
            info.error_message = "widgets.abc size is 0"
            return False
        else:
            info.abc_size += widgets_abc_size

    if is_debug:
        sourcemap_path = os.path.join(abc_sourcemap_path, 'sourceMaps.map')
        if not os.path.exists(sourcemap_path):
            info.result = options.TaskResult.failed
            info.error_message = "sourcemap not found"
            return False

    return True


def collect_compile_time(info, time_string):
    time_second = 0
    time_millisecond = 0

    time_items = time_string.split()
    for i in range(0, len(time_items)):
        if time_items[i] == 's':
            time_second = float(time_items[i - 1])
        if time_items[i] == 'ms':
            time_millisecond = round(float(time_items[i - 1])/1000, 3)

    info.time = round(time_second + time_millisecond, 3)


def get_compile_output_file_path(task, is_debug):
    output_file = ''

    if is_debug:
        output_file = os.path.join(task.path, *(task.build_path), *(task.output_hap_path))
    else:
        output_file = os.path.join(task.path, *(task.build_path), *(task.output_app_path))

    return output_file


def validate_compile_output(info, task, is_debug):
    passed = False

    output_file = get_compile_output_file_path(task, is_debug)
    uncompressed_output_file = output_file + '.uncompressed'

    if not os.path.exists(output_file):
        logging.error("output file for task %s not exists: %s", task.name, output_file)
        passed = False

        info.result = options.TaskResult.failed
        info.error_message = "Hap not found"
        return [passed, uncompressed_output_file]
    try:
        with zipfile.ZipFile(output_file, 'r') as zip_ref:
            zip_ref.extractall(uncompressed_output_file)
    except Exception as e:
        logging.error("unzip exception: %s", e)
        logging.error("uncompressed output file for task %s failed. output file: %s", task.name, output_file)
        passed = False

        info.result = options.TaskResult.failed
        info.error_message = "Hap uncompressed failed, cannot exam build products"
        return [passed, uncompressed_output_file]

    if utils.is_esmodule(task.type):
        passed = validate_output_for_esmodule(info, task.type, uncompressed_output_file, is_debug)
    else:
        passed = validate_output_for_jsbundle(info, uncompressed_output_file, is_debug)

    shutil.rmtree(uncompressed_output_file)

    return passed


def run_compile_output(info, task_path):
    ## TODO:
    # 1)install hap
    # 2)run hap and verify
    return


def is_compile_success(compile_stdout):
    pattern = r"BUILD SUCCESSFUL in (\d+ s )?(\d+ ms)?"
    match_result = re.search(pattern, compile_stdout)
    if not match_result:
        return [False, '']

    return [True, match_result.group(0)]


def validate(compilation_info, task, is_debug, stdout, stderr):
    info = {}
    if is_debug:
        info = compilation_info.debug_info
    else:
        info = compilation_info.release_info

    # ret_code will be 1 if there's stderr, use "COMPILE SUCCESSFUL" as a flag to make a judge
    [is_success, time_string] = is_compile_success(stdout)
    if not is_success:
        info.result = options.TaskResult.failed
        info.error_message = stderr
        return

    passed = False
    passed = validate_compile_output(info, task, is_debug)

    if not options.arguments.pack_only:
        passed = run_compile_output(info)

    if passed:
        collect_compile_time(info, time_string)
        info.result = options.TaskResult.passed

    return passed


def compile(task, is_debug):
    cmd = ['hvigorw']
    if is_debug:
        cmd.append('assembleHap')
    else:
        cmd.append('assembleApp')

    logging.debug('cmd: %s', cmd)
    logging.debug("cmd execution path %s", task.path)
    process = subprocess.Popen(cmd, shell = True, cwd = task.path,
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE)
    stdout, stderr = process.communicate(timeout=options.arguments.compile_timeout)
    stdout_utf8 = stdout.decode("utf-8", errors="ignore")
    stderr_utf8 = stderr.decode("utf-8", errors="ignore")
    logging.debug("cmd stdout: {}".format(stdout_utf8))
    logging.debug("cmd stderr: {}".format(stderr_utf8))

    return [stdout_utf8, stderr_utf8]


def clean_compile(task):
    cmd = 'hvigorw clean'
    logging.debug('cmd: %s', cmd)
    logging.debug("cmd execution path %s", task.path)
    process = subprocess.Popen(cmd, shell = True, cwd = task.path,
                     stdout = subprocess.PIPE,
                     stderr = subprocess.PIPE)
    out, err = process.communicate(timeout=options.arguments.compile_timeout)


def validate_compile_incremental_time(task, inc_task, is_debug):
    if is_debug:
        full_info = task.full_compilation_info.debug_info
        inc_info = inc_task.debug_info
    else:
        full_info = task.full_compilation_info.release_info
        inc_info = inc_task.release_info

    if full_info.time < inc_info.time:
        inc_info.result = options.TaskResult.failed
        inc_info.error_message = 'Incremental compile took more time than full compile.'


def prepare_incremental_task(task, task_name):
    if task_name in task.incre_compilation_info:
        inc_task = task.incre_compilation_info[task_name]
    else:
        inc_task = options.IncCompilationInfo()
        inc_task.name = task_name
        task.incre_compilation_info[task_name] = inc_task
    return inc_task


def compile_incremental_no_modify(task, is_debug):
    task_name = 'no_change'
    inc_task = prepare_incremental_task(task, task_name)

    [stdout, stderr] = compile(task, is_debug)
    passed = validate(inc_task, task, is_debug, stdout, stderr)
    validate_compile_incremental_time(task, inc_task, is_debug)


def compile_incremental_add_oneline(task, is_debug):
    task_name = 'add_oneline'
    inc_task = prepare_incremental_task(task, task_name)

    modify_file_item = task.inc_modify_file
    modify_file = os.path.join(task.path, *modify_file_item)
    modify_file_backup = modify_file + ".bak"
    shutil.copyfile(modify_file, modify_file_backup)

    with open(modify_file, 'a', encoding='utf-8') as file:
        file.write(options.configs['patch_content']['patch_lines_2']['tail'])

    [stdout, stderr] = compile(task, is_debug)
    passed = validate(inc_task, task, is_debug, stdout, stderr)
    validate_compile_incremental_time(task, inc_task, is_debug)

    shutil.move(modify_file_backup, modify_file)


def compile_incremental_add_file(task, is_debug):
    task_name = 'add_file'
    inc_task = prepare_incremental_task(task, task_name)

    modify_file_item = task.inc_modify_file
    modify_file = os.path.join(task.path, *modify_file_item)
    modify_file_backup = modify_file + ".bak"
    shutil.copyfile(modify_file, modify_file_backup)

    modify_dir = os.path.dirname(modify_file)
    new_file_name = options.configs['patch_content']['patch_new_file']['name']
    new_file_content = options.configs['patch_content']['patch_new_file']['content']
    new_file = os.path.join(modify_dir, new_file_name)

    with open(new_file, 'w', encoding='utf-8') as file:
        file.writelines(new_file_content)

    with open(modify_file, 'r+', encoding='utf-8') as file:
        old_content = file.read()
        file.seek(0)
        file.write(options.configs['patch_content']['patch_lines_1']['head'])
        file.write(old_content)
        file.write(options.configs['patch_content']['patch_lines_1']['tail'])

    [stdout, stderr] = compile(task, is_debug)
    validate(inc_task, task, is_debug, stdout, stderr)
    validate_compile_incremental_time(task, inc_task, is_debug)

    shutil.move(modify_file_backup, modify_file)
    os.remove(new_file)


def compile_incremental_delete_file(task, is_debug):
    task_name = 'delete_file'
    inc_task = prepare_incremental_task(task, task_name)

    # this test is after 'add_file', and in test 'add_file' already done remove file,
    # so here just call compile
    [stdout, stderr] = compile(task, is_debug)
    validate(inc_task, task, is_debug, stdout, stderr)
    validate_compile_incremental_time(task, inc_task, is_debug)


def compile_incremental_reverse_hap_mode(task, is_debug):
    task_name = 'reverse_hap_mode'
    inc_task = prepare_incremental_task(task, task_name)

    hap_mode = not is_debug
    [stdout, stderr] = compile(task, hap_mode)
    validate(inc_task, task, hap_mode, stdout, stderr)


def compile_incremental_modify_bundle_name(task, is_debug):
    # TODO: this needs to modify bundle name and disasm abc for compare
    return


def compile_incremental(task, is_debug):
    [stdout, stderr] = compile(task, is_debug)

    [is_success, time_string] = is_compile_success(stdout)
    if not is_success:
        logging.error("Incremental compile failed due to first compile failed!")
        return

    if options.arguments.compile_mode == 'incremental':
        passed = validate(task.full_compilation_info, task, is_debug, stdout, stderr)
        if not passed:
            logging.error("Incremental compile failed due to first compile failed!")
            return

    backup_compile_output(task, is_debug)

    compile_incremental_no_modify(task, is_debug)
    compile_incremental_add_oneline(task, is_debug)
    compile_incremental_add_file(task, is_debug)
    compile_incremental_delete_file(task, is_debug)
    compile_incremental_reverse_hap_mode(task, is_debug)
    # TODO: compile_incremental_modify_bundle_name(task, is_debug)


def backup_compile_output(task, is_debug):
    backup_path = task.backup_info.cache_path
    if not os.path.exists(backup_path):
        os.mkdir(backup_path)

    if is_debug:
        if len(task.backup_info.output_debug) == 2:
            return

        backup_output_path = os.path.join(backup_path, 'output', 'debug')
        if not os.path.exists(backup_output_path):
            os.makedirs(backup_output_path)
        output_file = get_compile_output_file_path(task, True)

    else:
        if len(task.backup_info.output_release) == 2:
            return

        backup_output_path = os.path.join(backup_path, 'output', 'release')
        if not os.path.exists(backup_output_path):
            os.makedirs(backup_output_path)
        output_file = get_compile_output_file_path(task, False)

    shutil.copy(output_file, backup_output_path)
    backup_output = os.path.join(backup_output_path, os.path.basename(output_file))
    backup_time_output = backup_output + '-' + utils.get_time_string()
    shutil.move(backup_output, backup_time_output)

    if is_debug:
        task.backup_info.output_debug.append(backup_time_output)
    else:
        task.backup_info.output_release.append(backup_time_output)


def backup_compile_cache(task, is_debug):
    backup_path = task.backup_info.cache_path
    if not os.path.exists(backup_path):
        os.mkdir(backup_path)

    backup_cache_path = os.path.join(backup_path, 'cache')
    if not os.path.exists(backup_cache_path):
        os.mkdir(backup_cache_path)
    cache_files = os.path.join(task.path, *(task.build_path), 'cache')

    if is_debug:
        if len(task.backup_info.cache_debug) == 1:
            return

        backup_cache_file = os.path.join(backup_cache_path, 'debug')
        shutil.copytree(cache_files, backup_cache_file)
        task.backup_info.cache_debug = backup_cache_file
    else:
        if len(task.backup_info.cache_release) == 1:
            return

        backup_cache_file = os.path.join(backup_cache_path, 'release')
        shutil.copytree(cache_files, backup_cache_file)
        task.backup_info.cache_release = backup_cache_file


def backup_compile_output_and_cache(task, is_debug):
    backup_compile_output(task, is_debug)
    backup_compile_cache(task, is_debug)


def execute_full_compile(task):
    clean_compile(task)
    passed = False
    if options.arguments.hap_mode in ['all', 'release']:
        [stdout, stderr] = compile(task, False)
        passed = validate(task.full_compilation_info, task, False, stdout, stderr)
        if passed:
            backup_compile_output_and_cache(task, False)
        clean_compile(task)
    if options.arguments.hap_mode in ['all', 'debug']:
        [stdout, stderr] = compile(task, True)
        passed = validate(task.full_compilation_info, task, True, stdout, stderr)
        if passed:
            backup_compile_output_and_cache(task, True)
        clean_compile(task)

    return passed


def execute_incremental_compile(task):
    if options.arguments.hap_mode in ['all', 'release']:
        compile_incremental(task, False)
    if options.arguments.hap_mode in ['all', 'debug']:
        compile_incremental(task, True)
    clean_compile(task)


def execute_break_compile(task):
    # TODO
    return ''


def verify_binary_consistency(task):
    debug_consistency = True
    release_consistency = True

    if options.arguments.hap_mode in ['all', 'release']:
        # will have at lease 1 output from full compile
        if len(task.backup_info.output_release) == 1:
            compile(task, False)
            backup_compile_output(task, False)

        if len(task.backup_info.output_release) == 2:
            release_consistency = utils.is_same_file(
                task.backup_info.output_release[0], task.backup_info.output_release[1])
        else:
            release_consistency = False

    if options.arguments.hap_mode in ['all', 'debug']:
        logging.debug("----> len cache: %s", len(task.backup_info.output_debug))
        if len(task.backup_info.output_debug) == 1:
            logging.debug("----> rebuild")
            compile(task, True)
            backup_compile_output(task, True)

        if len(task.backup_info.output_debug) == 2:
            logging.debug('-----> compare')
            debug_consistency = utils.is_same_file(
                task.backup_info.output_debug[0], task.backup_info.output_debug[1])
        else:
            debug_consistency = False

    if debug_consistency and release_consistency:
        task.abc_consistency = options.TaskResult.passed
    else:
        task.abc_consistency = options.TaskResult.failed


def clean_backup(task):
    if os.path.exists(task.backup_info.cache_path):
        shutil.rmtree(task.backup_info.cache_path)


def execute(test_tasks):
    for task in test_tasks:
        try:
            # TODO: add sdk path checking(sdk path in hap is same as config.yaml)
            logging.info("======> running task: %s", task.name)
            if options.arguments.compile_mode in ['all', 'full']:
                logging.info("==========> running task: %s in full compilation", task.name)
                if not execute_full_compile(task):
                    logging.error("Full compile failed, skip other tests!")
                    continue

            if options.arguments.compile_mode in ['all', 'incremental']:
                logging.info("==========> running task: %s in incremental compilation", task.name)
                execute_incremental_compile(task)

            execute_break_compile(task)
            verify_binary_consistency(task)
            logging.info("======> running task: %s finised", task.name)
        except Exception as e:
            logging.exception(e)
        finally:
            clean_backup(task)
