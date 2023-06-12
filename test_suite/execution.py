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
import json5
import os
import re
import shutil
import signal
import subprocess
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

    if 'widget' in task_type:
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


def get_hvigor_compile_cmd(is_debug):
    cmd = ['hvigorw']
    if is_debug:
        cmd.append('assembleHap')
    else:
        cmd.append('assembleApp')
    return cmd


def compile(task, is_debug):
    cmd = get_hvigor_compile_cmd(is_debug)

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


def validate_compile_incremental_file(task, inc_task, is_debug, modified_files):
    cache_extention = '.protoBin'
    modified_cache_files = []

    # modified_files is a list of file with relative path to .../debug/release
    for file in modified_files:
        name, ext = os.path.splitext(file)
        modified_cache_files.append(name + cache_extention)

    if is_debug:
        cache_path = os.path.join(task.path, *(task.build_path), *(task.cache_path), 'debug')
        backup_path = task.backup_info.cache_debug
        inc_info = inc_task.debug_info
    else:
        cache_path = os.path.join(task.path, *(task.build_path), *(task.cache_path), 'release')
        backup_path = task.backup_info.cache_release
        inc_info = inc_task.release_info

    for root, dirs, files in os.walk(cache_path):
        for file in files:
            name, extension = os.path.splitext(file)
            if extension == cache_extention:
                file_absolute_path = os.path.join(root, file)
                file_relative_path = os.path.relpath(file_absolute_path, cache_path)
                backup_file = os.path.join(backup_path, file_relative_path)

                if not os.path.exists(backup_file):
                    logging.debug("backup file not exits: %s", backup_file)
                    continue

                logging.debug("time stamp same: %s", utils.is_file_timestamps_same(file_absolute_path, backup_file))
                logging.debug("file_relative_path %s", file_relative_path)
                logging.debug("file not in list: %s", file_relative_path not in modified_cache_files)
                logging.debug("file list: %s", modified_cache_files)

                if not utils.is_file_timestamps_same(file_absolute_path, backup_file) and \
                    file_relative_path not in modified_cache_files:
                    inc_info.result = options.TaskResult.failed
                    inc_info.error_message = 'Incremental compile found unexpected file timestamp changed. Changed file: ' + file_relative_path
                    return


def prepare_incremental_task(task, test_name):
    if test_name in task.incre_compilation_info:
        inc_task = task.incre_compilation_info[test_name]
    else:
        inc_task = options.IncCompilationInfo()
        inc_task.name = test_name
        task.incre_compilation_info[test_name] = inc_task
    return inc_task


def compile_incremental_no_modify(task, is_debug):
    test_name = 'no_change'
    inc_task = prepare_incremental_task(task, test_name)

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    [stdout, stderr] = compile(task, is_debug)
    passed = validate(inc_task, task, is_debug, stdout, stderr)
    if passed:
        validate_compile_incremental_file(task, inc_task, is_debug, [])


def compile_incremental_add_oneline(task, is_debug):
    test_name = 'add_oneline'
    inc_task = prepare_incremental_task(task, test_name)

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    modify_file_item = task.inc_modify_file
    modify_file = os.path.join(task.path, *modify_file_item)
    modify_file_backup = modify_file + ".bak"
    shutil.copyfile(modify_file, modify_file_backup)

    with open(modify_file, 'a', encoding='utf-8') as file:
        file.write(options.configs['patch_content']['patch_lines_2']['tail'])

    [stdout, stderr] = compile(task, is_debug)
    passed = validate(inc_task, task, is_debug, stdout, stderr)
    if passed:
        modified_files = [os.path.join(*modify_file_item)]
        validate_compile_incremental_file(task, inc_task, is_debug, modified_files)

    shutil.move(modify_file_backup, modify_file)


def compile_incremental_add_file(task, is_debug):
    test_name = 'add_file'
    inc_task = prepare_incremental_task(task, test_name)

    logging.info("==========> Running %s for task: %s", test_name, task.name)
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
    passed = validate(inc_task, task, is_debug, stdout, stderr)
    if passed:
        modified_files = [os.path.join(*modify_file_item)]
        validate_compile_incremental_file(task, inc_task, is_debug, modified_files)

    shutil.move(modify_file_backup, modify_file)
    os.remove(new_file)


def compile_incremental_delete_file(task, is_debug):
    test_name = 'delete_file'
    inc_task = prepare_incremental_task(task, test_name)

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    # this test is after 'add_file', and in test 'add_file' already done remove file,
    # so here just call compile
    [stdout, stderr] = compile(task, is_debug)
    passed = validate(inc_task, task, is_debug, stdout, stderr)
    if passed:
        modify_file_item = task.inc_modify_file
        modified_files = [os.path.join(*modify_file_item)]
        validate_compile_incremental_file(task, inc_task, is_debug, modified_files)


def compile_incremental_reverse_hap_mode(task, is_debug):
    test_name = 'reverse_hap_mode'
    inc_task = prepare_incremental_task(task, test_name)

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    hap_mode = not is_debug
    [stdout, stderr] = compile(task, hap_mode)
    validate(inc_task, task, hap_mode, stdout, stderr)


def compile_incremental_modify_bundle_name(task, is_debug):
    # TODO: this needs to modify bundle name and disasm abc for compare
    return


def compile_incremental(task, is_debug):
    logging.info("==========> Running task: %s in incremental compilation", task.name)
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
    backup_compile_cache(task, is_debug)

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

    else:
        if len(task.backup_info.output_release) == 2:
            return

        backup_output_path = os.path.join(backup_path, 'output', 'release')
        if not os.path.exists(backup_output_path):
            os.makedirs(backup_output_path)

    output_file = get_compile_output_file_path(task, is_debug)
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
    cache_files = os.path.join(task.path, *(task.build_path), *(task.cache_path))

    if is_debug:
        if task.backup_info.cache_debug != '':
            return

        cache_files = os.path.join(cache_files, 'debug')
        backup_cache_file = os.path.join(backup_cache_path, 'debug')
        shutil.copytree(cache_files, backup_cache_file)
        task.backup_info.cache_debug = backup_cache_file
    else:
        if task.backup_info.cache_release != '':
            return

        cache_files = os.path.join(cache_files, 'release')
        backup_cache_file = os.path.join(backup_cache_path, 'release')
        shutil.copytree(cache_files, backup_cache_file)
        task.backup_info.cache_release = backup_cache_file


def is_abc_same_in_haps(hap_1, hap_2):
    hap_1_abc_files = []
    hap_2_abc_files = []
    with zipfile.ZipFile(hap_1) as zf1, zipfile.ZipFile(hap_2) as zf2:
        for file in zf1.namelist():
            if file.endswith('.abc'):
                hap_1_abc_files.append(file)
        for file in zf2.namelist():
            if file.endswith('.abc'):
                hap_2_abc_files.append(file)

        hap_1_abc_files.sort()
        hap_2_abc_files.sort()

        if len(hap_1_abc_files) != len(hap_2_abc_files):
            return False

        for idx in range(len(hap_1_abc_files)):
            with zf1.open(hap_1_abc_files[idx]) as f1, zf2.open(hap_2_abc_files[idx]) as f2:
                data1 = f1.read()
                data2 = f2.read()
                if data1 != data2:
                    return False

    return True


def execute_full_compile(task):
    logging.info("==========> Running task: %s in full compilation", task.name)
    clean_compile(task)
    passed = False
    if options.arguments.hap_mode in ['all', 'release']:
        [stdout, stderr] = compile(task, False)
        passed = validate(task.full_compilation_info, task, False, stdout, stderr)
        if passed:
            backup_compile_output(task, False)
        clean_compile(task)
    if options.arguments.hap_mode in ['all', 'debug']:
        [stdout, stderr] = compile(task, True)
        passed = validate(task.full_compilation_info, task, True, stdout, stderr)
        if passed:
            backup_compile_output(task, True)
        clean_compile(task)

    return passed


def execute_incremental_compile(task):
    logging.info("==========> Running task: %s in incremental compilation", task.name)
    if options.arguments.hap_mode in ['all', 'release']:
        compile_incremental(task, False)
    if options.arguments.hap_mode in ['all', 'debug']:
        compile_incremental(task, True)
    clean_compile(task)


def verify_binary_consistency(task):
    test_name = 'binary_consistency'
    test_info = options.CompilationInfo()
    debug_consistency = True
    release_consistency = True

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    if options.arguments.hap_mode in ['all', 'release']:
        # will have at lease 1 output from full compile
        if len(task.backup_info.output_release) == 1:
            compile(task, False)
            backup_compile_output(task, False)

        if len(task.backup_info.output_release) == 2:
            release_consistency = is_abc_same_in_haps(task.backup_info.output_release[0],
                                                      task.backup_info.output_release[1])
        else:
            release_consistency = False
        logging.debug("release consistency: %s", release_consistency)

    if options.arguments.hap_mode in ['all', 'debug']:
        if len(task.backup_info.output_debug) == 1:
            compile(task, True)
            backup_compile_output(task, True)

        if len(task.backup_info.output_debug) == 2:
            debug_consistency = is_abc_same_in_haps(task.backup_info.output_debug[0],
                                                    task.backup_info.output_debug[1])
        else:
            debug_consistency = False
        logging.debug("debug consistency: %s", debug_consistency)

    if debug_consistency and release_consistency:
        test_info.result = options.TaskResult.passed
    else:
        test_info.result = options.TaskResult.failed

    task.other_tests[test_name] = test_info


def execute_break_compile(task, is_debug):
    test_name = 'break_continue_compile'
    test_info = options.CompilationInfo()

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    clean_compile(task)
    cmd = get_hvigor_compile_cmd(is_debug)
    logging.debug('cmd: %s', cmd)
    logging.debug("cmd execution path %s", task.path)
    process = subprocess.Popen(cmd, shell = True, cwd = task.path,
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE)

    # TODO: this is signal seems to sent after the build process finished. Check
    # this in a longer build time app later
    for line in iter(process.stdout.readline, b''):
        if b'CompileArkTS' in line:
            logging.debug("terminate signal sent")
            process.send_signal(signal.SIGTERM)
            break

    [stdout, stderr] = process.communicate()

    logging.debug("first compile: stdcout: {}".format(stdout.decode('utf-8', errors="ignore")))
    logging.debug("first compile: stdcerr: {}".format(stderr.decode('utf-8', errors="ignore")))

    logging.debug("another compile")
    [stdout, stderr] = compile(task, is_debug)

    [is_success, time_string] = is_compile_success(stdout)
    if not is_success:
        test_info.result = options.TaskResult.failed
        test_info.error_message = stderr
    else:
        passed = validate_compile_output(test_info, task, is_debug)
        if passed:
            test_info.result = options.TaskResult.passed

    task.other_tests[test_name] = test_info


def compile_full_with_error(task, is_debug):
    test_name = 'compile_with_error'
    test_info = options.CompilationInfo()

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    modify_file_item = task.inc_modify_file
    modify_file = os.path.join(task.path, *modify_file_item)
    modify_file_backup = modify_file + ".bak"
    shutil.copyfile(modify_file, modify_file_backup)

    with open(modify_file, 'a', encoding='utf-8') as file:
        file.write(options.configs['patch_content']['patch_lines_error']['tail'])

    [stdout, stderr] = compile(task, is_debug)
    expected_error_message = options.configs['patch_content']['patch_lines_error']['expected_error']

    if expected_error_message in stderr:
        test_info.result = options.TaskResult.passed
    else:
        test_info.result = options.TaskResult.failed
        test_info.error_message = "expected error message: {}, but got {}".format(expected_error_message, stderr)

    task.other_tests[test_name] = test_info

    shutil.move(modify_file_backup, modify_file)


def compile_with_exceed_length(task, is_debug):
    test_name = 'compile_with_exceed_length'
    test_info = options.CompilationInfo()

    logging.info("==========> Running %s for task: %s", test_name, task.name)
    # get build-profile.json5
    entry_item = task.build_path[:-2]  # to entry path
    profile_file = os.path.join(task.path, *entry_item, 'build-profile.json5')
    profile_file_backup = profile_file + ".bak"
    shutil.copyfile(profile_file, profile_file_backup)

    with open(profile_file, 'r') as file:
        profile_data = json5.load(file)

    long_str = 'default123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
    profile_data['targets'][0]['name'] = long_str

    with open(profile_file, 'w') as file:
        json5.dump(profile_data, file)

    [stdout, stderr] = compile(task, is_debug)
    expected_error_message = 'The length of path exceeds the maximum length: 259'

    if expected_error_message in stderr:
        test_info.result = options.TaskResult.passed
    else:
        test_info.result = options.TaskResult.failed
        test_info.error_message = "expected error message: {}, but got {}".format(expected_error_message, stderr)

    task.other_tests[test_name] = test_info

    shutil.move(profile_file_backup, profile_file)


def compile_ohos_test(task):
    return


def clean_backup(task):
    if os.path.exists(task.backup_info.cache_path):
        shutil.rmtree(task.backup_info.cache_path)
    return


def execute(test_tasks):
    for task in test_tasks:
        try:
            # TODO: add sdk path checking(sdk path in hap is same as config.yaml)
            logging.info("======> Running task: %s", task.name)
            if options.arguments.compile_mode in ['all', 'full']:
                if not execute_full_compile(task):
                    logging.info("Full compile failed, skip other tests!")
                    continue

            if options.arguments.compile_mode in ['all', 'incremental']:
                execute_incremental_compile(task)

            verify_binary_consistency(task)

            # for these tests, use one hapMode maybe enough
            is_debug = True if options.arguments.hap_mode == 'debug' else False
            execute_break_compile(task, is_debug)
            if 'error' in task.type:
                compile_full_with_error(task, is_debug)

            if 'exceed_length_error' in task.type:
                compile_with_exceed_length(task, is_debug)

            if 'ohosTest' in task.type:
                compile_ohos_test(task)

            logging.info("======> Running task: %s finised", task.name)
        except Exception as e:
            logging.exception(e)
        finally:
            clean_backup(task)