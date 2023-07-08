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
import shutil
import signal
import subprocess
import zipfile

import json5

import options
import utils


class IncrementalTest:
    @staticmethod
    def validate_module_name_change(task, inc_task, is_debug, stdout, stderr, new_module_name):
        output_file = get_compile_output_file_path(task, is_debug)
        output_dir = os.path.dirname(output_file)
        output_file_name = os.path.basename(output_file)
        output_file_name_items = output_file_name.split(
            '-')  # hap name format: entry-default.hap
        output_file_name_items[0] = new_module_name
        output_file_name = '-'.join(output_file_name_items)
        new_module_name_output_file = os.path.join(
            output_dir, output_file_name)

        logging.debug(f"new module hap file: {new_module_name_output_file}")

        passed = validate(inc_task, task, is_debug, stdout,
                          stderr, new_module_name_output_file)
        logging.debug(f"validate new module hap file, passed {passed}")
        if not passed:
            return

        if is_debug:
            inc_info = inc_task.debug_info
        else:
            inc_info = inc_task.release_info
        uncompressed_output_file = new_module_name_output_file + '.uncompressed'
        with zipfile.ZipFile(new_module_name_output_file, 'r') as zip_ref:
            zip_ref.extractall(uncompressed_output_file)

        abc_path = os.path.join(uncompressed_output_file, 'ets')
        modules_abc_path = os.path.join(abc_path, 'modules.abc')
        modules_pa = disasm_abc(modules_abc_path)
        if not modules_pa or not os.path.exists(modules_pa):
            inc_info.result = options.TaskResult.failed
            inc_info.error_message = f'ark_disasm failed, module name change not verified'
            return

        func_str = ''
        with open(modules_pa, 'r', encoding='utf-8') as pa:
            line = pa.readline()
            while line:
                if '.function' in line.strip():
                    func_str = line.strip()
                    break
                line = pa.readline()

        func_define_items = func_str.split('.')
        if not new_module_name in func_define_items:
            inc_info.result = options.TaskResult.failed
            inc_info.error_message = f'expected entry name {new_module_name} in function name, \
                                     actual function name: {func_str}'

        shutil.rmtree(uncompressed_output_file)

    @staticmethod
    def is_file_in_modified_files(task_type, backup_file_relative_path, modified_cache_files):
        if 'stage' in task_type:
            return backup_file_relative_path in modified_cache_files
        else:
            non_temporary_path = backup_file_relative_path.split("temporary")[
                1].lstrip(os.path.sep)
            logging.debug(f"non_temporary_path: {non_temporary_path}")
            for file in modified_cache_files:
                logging.debug(f"modified_cache_files file: {file}")
                if non_temporary_path in file:
                    return True
        return False

    @staticmethod
    def validate_compile_incremental_file(task, inc_task, is_debug, modified_files):
        cache_extension = ''
        if 'stage' in task.type:
            cache_extention = '.protoBin'
        elif 'fa' in task.type or 'compatible8' in task.type:
            cache_extention = '.temp.abc'
        elif 'js' in task.type:
            cache_extention = '.abc'

        modified_cache_files = []
        # modified_files is a list of file with relative path to .../debug/release
        for file in modified_files:
            name, ext = os.path.splitext(file)
            modified_cache_files.append(name + cache_extention)

        logging.debug(f"modified_cache_files: {modified_cache_files}")

        if is_debug:
            cache_path = os.path.join(
                task.path, *(task.build_path), *(task.cache_path), 'debug')
            backup_path = task.backup_info.cache_debug
            inc_info = inc_task.debug_info
        else:
            cache_path = os.path.join(
                task.path, *(task.build_path), *(task.cache_path), 'release')
            backup_path = task.backup_info.cache_release
            inc_info = inc_task.release_info

        for root, dirs, files in os.walk(cache_path):
            for file in files:
                if not file.endswith(cache_extention):
                    continue
                file_absolute_path = os.path.join(root, file)
                file_relative_path = os.path.relpath(
                    file_absolute_path, cache_path)
                backup_file = os.path.join(backup_path, file_relative_path)

                if not os.path.exists(backup_file):
                    logging.debug(f"backup file not exits: {backup_file}")
                    continue

                if utils.is_file_timestamps_same(file_absolute_path, backup_file):
                    continue

                logging.debug(f"found file ${file_relative_path} changed")
                is_file_in_list = IncrementalTest.is_file_in_modified_files(
                    task.type, file_relative_path, modified_cache_files)
                logging.debug(f"is file in list: {is_file_in_list}")
                if not is_file_in_list:
                    inc_info.result = options.TaskResult.failed
                    inc_info.error_message = f'Incremental compile found unexpected file timestamp changed. \
                                             Changed file: {file_relative_path}'
                    return

    @staticmethod
    def prepare_incremental_task(task, test_name):
        if test_name in task.incre_compilation_info:
            inc_task = task.incre_compilation_info[test_name]
        else:
            inc_task = options.IncCompilationInfo()
            inc_task.name = test_name
            task.incre_compilation_info[test_name] = inc_task
        return inc_task

    @staticmethod
    def compile_incremental_no_modify(task, is_debug):
        test_name = 'no_change'
        inc_task = IncrementalTest.prepare_incremental_task(task, test_name)

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        [stdout, stderr] = compile_project(task, is_debug)
        passed = validate(inc_task, task, is_debug, stdout, stderr)
        if passed:
            IncrementalTest.validate_compile_incremental_file(
                task, inc_task, is_debug, [])

    @staticmethod
    def compile_incremental_add_oneline(task, is_debug):
        test_name = 'add_oneline'
        inc_task = IncrementalTest.prepare_incremental_task(task, test_name)

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        modify_file_item = task.inc_modify_file
        modify_file = os.path.join(task.path, *modify_file_item)
        modify_file_backup = modify_file + ".bak"
        shutil.copyfile(modify_file, modify_file_backup)

        with open(modify_file, 'a', encoding='utf-8') as file:
            file.write(options.configs.get('patch_content').get(
                'patch_lines_2').get('tail'))

        [stdout, stderr] = compile_project(task, is_debug)
        passed = validate(inc_task, task, is_debug, stdout, stderr)
        if passed:
            modified_files = [os.path.join(*modify_file_item)]
            IncrementalTest.validate_compile_incremental_file(
                task, inc_task, is_debug, modified_files)

        shutil.move(modify_file_backup, modify_file)

    @staticmethod
    def compile_incremental_add_file(task, is_debug):
        test_name = 'add_file'
        inc_task = IncrementalTest.prepare_incremental_task(task, test_name)

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        modify_file_item = task.inc_modify_file
        modify_file = os.path.join(task.path, *modify_file_item)
        modify_file_backup = modify_file + ".bak"
        shutil.copyfile(modify_file, modify_file_backup)

        modify_dir = os.path.dirname(modify_file)
        if 'js' in task.type:
            patch_content = options.configs.get(
                'patch_content').get('patch_new_file_js')
            new_file_name = patch_content.get('name')
            new_file_content = patch_content.get('content')
        else:
            patch_content = options.configs.get(
                'patch_content').get('patch_new_file_ets')
            new_file_name = patch_content.get('name')
            new_file_content = patch_content.get('content')
        new_file = os.path.join(modify_dir, new_file_name)

        with open(new_file, 'w', encoding='utf-8') as file:
            file.writelines(new_file_content)

        with open(modify_file, 'r+', encoding='utf-8') as file:
            old_content = file.read()
            file.seek(0)
            patch_lines = options.configs.get(
                'patch_content').get('patch_lines_1')
            file.write(patch_lines.get('head'))
            file.write(old_content)
            file.write(patch_lines.get('tail'))

        [stdout, stderr] = compile_project(task, is_debug)
        passed = validate(inc_task, task, is_debug, stdout, stderr)
        if passed:
            modified_files = [os.path.join(*modify_file_item)]
            IncrementalTest.validate_compile_incremental_file(
                task, inc_task, is_debug, modified_files)

        shutil.move(modify_file_backup, modify_file)
        os.remove(new_file)

    @staticmethod
    def compile_incremental_delete_file(task, is_debug):
        test_name = 'delete_file'
        inc_task = IncrementalTest.prepare_incremental_task(task, test_name)

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        # this test is after 'add_file', and in test 'add_file' already done remove file,
        # so here just call compile
        [stdout, stderr] = compile_project(task, is_debug)
        passed = validate(inc_task, task, is_debug, stdout, stderr)
        if passed:
            modify_file_item = task.inc_modify_file
            modified_files = [os.path.join(*modify_file_item)]
            IncrementalTest.validate_compile_incremental_file(
                task, inc_task, is_debug, modified_files)

    @staticmethod
    def compile_incremental_reverse_hap_mode(task, is_debug):
        test_name = 'reverse_hap_mode'
        inc_task = IncrementalTest.prepare_incremental_task(task, test_name)

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        hap_mode = not is_debug
        [stdout, stderr] = compile_project(task, hap_mode)
        validate(inc_task, task, hap_mode, stdout, stderr)

    @staticmethod
    def compile_incremental_modify_module_name(task, is_debug):
        if 'stage' not in task.type:
            return

        test_name = 'change_module_name'
        inc_task = IncrementalTest.prepare_incremental_task(task, test_name)

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        # modify build-profile.json5
        profile_file = os.path.join(task.path, 'build-profile.json5')
        profile_file_backup = profile_file + ".bak"
        shutil.copyfile(profile_file, profile_file_backup)

        with open(profile_file, 'r') as file:
            profile_data = json5.load(file)
        new_module_name = "new_entry"
        logging.debug(f"profile_data is: {profile_data}")
        profile_data['modules'][0]['name'] = new_module_name
        with open(profile_file, 'w') as file:
            json5.dump(profile_data, file)

        # modify module.json5 for stage mode
        entry_item = task.build_path[:-2]  # to entry path
        config_file_dir = os.path.join(task.path, *entry_item, 'src', 'main')
        config_file = os.path.join(config_file_dir, 'module.json5')
        config_file_backup = config_file + ".bak"
        shutil.copyfile(config_file, config_file_backup)

        with open(config_file, 'r') as file:
            config_data = json5.load(file)
        config_data['module']['name'] = new_module_name
        with open(config_file, 'w') as file:
            json5.dump(config_data, file)

        try:
            [stdout, stderr] = compile_project(task, is_debug)
            IncrementalTest.validate_module_name_change(
                task, inc_task, is_debug, stdout, stderr, new_module_name)
        except Exception as e:
            logging.exception(e)
        finally:
            shutil.move(profile_file_backup, profile_file)
            shutil.move(config_file_backup, config_file)


class OtherTest:
    @staticmethod
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

            for idx, abc_file in enumerate(hap_1_abc_files):
                with zf1.open(abc_file) as f1, zf2.open(hap_2_abc_files[idx]) as f2:
                    data1 = f1.read()
                    data2 = f2.read()
                    if data1 != data2:
                        return False

        return True

    @staticmethod
    def verify_binary_consistency(task):
        test_name = 'binary_consistency'
        test_info = options.CompilationInfo()
        task.other_tests[test_name] = test_info
        debug_consistency = True
        release_consistency = True

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        if options.arguments.hap_mode in ['all', 'release']:
            # will have at lease 1 output from full compile
            if len(task.backup_info.output_release) == 1:
                compile_project(task, False)
                backup_compile_output(task, False)

            if len(task.backup_info.output_release) == 2:
                release_consistency = OtherTest.is_abc_same_in_haps(task.backup_info.output_release[0],
                                                                    task.backup_info.output_release[1])
            else:
                release_consistency = False
            logging.debug(f"release consistency: {release_consistency}")

        if options.arguments.hap_mode in ['all', 'debug']:
            if len(task.backup_info.output_debug) == 1:
                compile_project(task, True)
                backup_compile_output(task, True)

            if len(task.backup_info.output_debug) == 2:
                debug_consistency = OtherTest.is_abc_same_in_haps(task.backup_info.output_debug[0],
                                                                  task.backup_info.output_debug[1])
            else:
                debug_consistency = False
            logging.debug(f"debug consistency: {debug_consistency}")

        if debug_consistency and release_consistency:
            test_info.result = options.TaskResult.passed
        else:
            test_info.result = options.TaskResult.failed

    @staticmethod
    def execute_break_compile(task, is_debug):
        test_name = 'break_continue_compile'
        test_info = options.CompilationInfo()
        task.other_tests[test_name] = test_info

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        clean_compile(task)
        cmd = get_hvigor_compile_cmd(task.path, is_debug)
        logging.debug(f'cmd: {cmd}')
        logging.debug(f"cmd execution path {task.path}")
        process = subprocess.Popen(cmd, shell=False, cwd=task.path,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        for line in iter(process.stdout.readline, b''):
            if b'CompileArkTS' in line:
                logging.debug("terminate signal sent")
                process.send_signal(signal.SIGTERM)
                break

        [stdout, stderr] = process.communicate(
            timeout=options.arguments.compile_timeout)

        logging.debug("first compile: stdcout: %s",
                      stdout.decode('utf-8', errors="ignore"))
        logging.warning("first compile: stdcerr: %s",
                        stderr.decode('utf-8', errors="ignore"))

        logging.debug("another compile")
        [stdout, stderr] = compile_project(task, is_debug)

        [is_success, time_string] = is_compile_success(stdout)
        if not is_success:
            test_info.result = options.TaskResult.failed
            test_info.error_message = stderr
        else:
            passed = validate_compile_output(test_info, task, is_debug)
            if passed:
                test_info.result = options.TaskResult.passed

    @staticmethod
    def compile_full_with_error(task, is_debug):
        test_name = 'compile_with_error'
        test_info = options.CompilationInfo()
        task.other_tests[test_name] = test_info

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        modify_file_item = task.inc_modify_file
        modify_file = os.path.join(task.path, *modify_file_item)
        modify_file_backup = modify_file + ".bak"
        shutil.copyfile(modify_file, modify_file_backup)

        patch_lines_error = options.configs.get(
            'patch_content').get('patch_lines_error')
        with open(modify_file, 'a', encoding='utf-8') as file:
            file.write(patch_lines_error.get('tail'))

        [stdout, stderr] = compile_project(task, is_debug)
        expected_errors = patch_lines_error.get('expected_error')

        passed = False
        for expected_error in expected_errors:
            if expected_error in stderr:
                passed = True
                break

        if passed:
            test_info.result = options.TaskResult.passed
        else:
            test_info.result = options.TaskResult.failed
            test_info.error_message = f"expected error message: {expected_errors}, but got {stderr}"

        shutil.move(modify_file_backup, modify_file)

    @staticmethod
    def compile_with_exceed_length(task, is_debug):
        test_name = 'compile_with_exceed_length'
        test_info = options.CompilationInfo()
        task.other_tests[test_name] = test_info

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        # get build-profile.json5
        entry_item = task.build_path[:-2]  # to entry path
        profile_file = os.path.join(
            task.path, *entry_item, 'build-profile.json5')
        profile_file_backup = profile_file + ".bak"
        shutil.copyfile(profile_file, profile_file_backup)

        with open(profile_file, 'r') as file:
            profile_data = json5.load(file)

        long_str = 'default1234567890123456789012345678901234567890123456789012345678901234567890123456789' + \
                   '012345678901234567890123456789'
        logging.debug("long_str: %s", long_str)
        profile_data['targets'][0]['name'] = long_str

        with open(profile_file, 'w') as file:
            json5.dump(profile_data, file)

        [stdout, stderr] = compile_project(task, is_debug)
        # Only the Windows platform has a length limit
        if utils.is_windows():
            expected_error_message = 'The length of path exceeds the maximum length: 259'

            if expected_error_message in stderr:
                test_info.result = options.TaskResult.passed
            else:
                test_info.result = options.TaskResult.failed
                test_info.error_message = f"expected error message: {expected_error_message}, but got {stderr}"
        else:
            [is_success, time_string] = is_compile_success(stdout)
            if not is_success:
                test_info.result = options.TaskResult.failed
                test_info.error_message = stderr
            else:
                passed = validate_compile_output(test_info, task, is_debug)
                if passed:
                    test_info.result = options.TaskResult.passed

        shutil.move(profile_file_backup, profile_file)

    @staticmethod
    def compile_ohos_test(task):
        test_name = 'ohos_test'
        test_info = options.CompilationInfo()
        task.other_tests[test_name] = test_info

        logging.info(f"==========> Running {test_name} for task: {task.name}")
        # ohosTest has only debug mode
        cmd = [get_hvigor_path(task.path), '--mode', 'module',
               '-p', 'module=entry@ohosTest', 'assembleHap']
        [stdout, stderr] = compile_project(task, True, cmd)
        [is_success, time_string] = is_compile_success(stdout)
        if not is_success:
            test_info.result = options.TaskResult.failed
            test_info.error_message = stderr
        else:
            output_file = get_compile_output_file_path(task, True)
            output_dir = os.path.dirname(output_file)
            output_file_name = os.path.basename(output_file)

            ohos_test_str = 'ohosTest'
            output_file_name_items = output_file_name.split(
                '-')  # hap name format: entry-default-signed.hap
            # ohosTest hap format: entry-ohosTest-signed.hap
            output_file_name_items[-2] = ohos_test_str
            output_file_name = '-'.join(output_file_name_items)

            output_dir_items = output_dir.split(os.path.sep)
            output_dir_items[-1] = ohos_test_str
            if utils.is_windows():
                # for windows, need to add an empty string to mark between disk identifier and path
                output_dir_items.insert(1, os.path.sep)
            elif utils.is_mac():
                output_dir_items.insert(0, os.path.sep)
            ohos_test_output_file = os.path.join(
                *output_dir_items, output_file_name)

            passed = validate_compile_output(
                test_info, task, True, ohos_test_output_file)
            if passed:
                test_info.result = options.TaskResult.passed


def disasm_abc(abc_file):
    sdk_path = options.configs.get('deveco_sdk_path')
    ark_disasm_path = ''
    if utils.is_windows():
        ark_disasm = 'ark_disasm.exe'
    else:
        ark_disasm = 'ark_disasm'
    # try to find ark_disasm in api 10, api 9 sequentially
    ark_disasm_10_path = os.path.join(sdk_path, '10', 'toolchains', ark_disasm)
    ark_disasm_9_path = os.path.join(sdk_path, '9', 'toolchains', ark_disasm)
    if os.path.exists(ark_disasm_10_path):
        ark_disasm_path = ark_disasm_10_path
    elif os.path.exists(ark_disasm_9_path):
        ark_disasm_path = ark_disasm_9_path
    else:
        logging.error("ark_disasm executable not found")
        return ''

    pa_file = abc_file + '.pa'
    cmd = [ark_disasm_path, '--verbose', abc_file, pa_file]
    logging.debug(f'cmd: {cmd}')
    process = subprocess.Popen(
        cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    [stdout, stderr] = process.communicate(
        timeout=options.arguments.compile_timeout)

    logging.debug("disasm stdcout: %s",
                  stdout.decode('utf-8', errors="ignore"))
    logging.warning("disasm: stdcerr: %s",
                    stderr.decode('utf-8', errors="ignore"))

    return pa_file


def is_abc_debug_info_correct(abc_file, is_debug):
    pa_file = disasm_abc(abc_file)
    if not os.path.exists(pa_file):
        logging.error(f"pa file not exist: {pa_file}")
        return False

    debug_info_block_str = 'LOCAL_VARIABLE_TABLE'
    has_debug_info_block = False
    with open(pa_file, 'r', encoding='utf-8') as pa:
        line = pa.readline()
        while line:
            if debug_info_block_str in line.strip():
                has_debug_info_block = True
                break
            line = pa.readline()

    if is_debug:
        return has_debug_info_block
    else:
        return not has_debug_info_block


def validate_output_for_jsbundle(info, task, uncompressed_output_path, is_debug):
    abc_files = []
    for root, dirs, files in os.walk(uncompressed_output_path):
        for file in files:
            if file.endswith('.abc'):
                abc_files.append(os.path.join(root, file))

    total_size = 0
    for file in abc_files:
        total_size += os.path.getsize(
            os.path.join(uncompressed_output_path, file))
        if 'compatible8' not in task.type and not is_abc_debug_info_correct(file, is_debug):
            # skip compatible8 outputs as disasm may failed
            info.result = options.TaskResult.failed
            info.error_message = f"{file} debug info not correct"
            return False

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


def validate_output_for_esmodule(info, task, uncompressed_output_path, is_debug):
    abc_generated_path = os.path.join(uncompressed_output_path, 'ets')

    modules_abc_path = os.path.join(abc_generated_path, 'modules.abc')
    if not os.path.exists(modules_abc_path):
        info.result = options.TaskResult.failed
        info.error_message = "modules.abc not found"
        return False

    modules_abc_size = os.path.getsize(modules_abc_path)
    if modules_abc_size <= 0:
        info.result = options.TaskResult.failed
        info.error_message = "modules.abc size is 0"
        return False
    if not is_abc_debug_info_correct(modules_abc_path, is_debug):
        info.result = options.TaskResult.failed
        info.error_message = "modules.abc debug info not correct"
        return False
    info.abc_size = modules_abc_size

    if 'widget' in task.type:
        widget_abc_path = os.path.join(abc_generated_path, 'widgets.abc')
        if not os.path.exists(widget_abc_path):
            info.result = options.TaskResult.failed
            info.error_message = "widgets.abc not found"
            return False

        widgets_abc_size = os.path.getsize(widget_abc_path)
        if widgets_abc_size <= 0:
            info.result = options.TaskResult.failed
            info.error_message = "widgets.abc size is 0"
            return False
        if not is_abc_debug_info_correct(widget_abc_path, is_debug):
            info.result = options.TaskResult.failed
            info.error_message = "widgets.abc debug info not correct"
            return False
        info.abc_size += widgets_abc_size

    if is_debug:
        sourcemap_path = abc_generated_path
    else:
        sourcemap_path = os.path.join(
            task.path, *(task.build_path), *(task.cache_path), 'release')
    sourcemap_file = os.path.join(sourcemap_path, 'sourceMaps.map')
    if not os.path.exists(sourcemap_file):
        info.result = options.TaskResult.failed
        info.error_message = "sourcemap not found"
        return False

    return True


def collect_compile_time(info, time_string):
    time_min = 0.0
    time_second = 0.0
    time_millisecond = 0.0

    time_items = time_string.split()
    for idx, item in enumerate(time_items):
        if item == 'min':
            time_min = float(time_items[idx - 1]) * 60
        if item == 's':
            time_second = float(time_items[idx - 1])
        if item == 'ms':
            time_millisecond = round(float(time_items[idx - 1]) / 1000, 3)

    info.time = round(time_min + time_second + time_millisecond, 3)


def get_compile_output_file_path(task, is_debug):
    output_file = ''

    if is_debug:
        output_file = os.path.join(
            task.path, *(task.build_path), *(task.output_hap_path))
    else:
        output_file = os.path.join(
            task.path, *(task.build_path), *(task.output_app_path))

    return output_file


def validate_compile_output(info, task, is_debug, output_file=''):
    passed = False

    if output_file == '':
        output_file = get_compile_output_file_path(task, is_debug)
    uncompressed_output_file = output_file + '.uncompressed'

    if not os.path.exists(output_file):
        logging.error("output file for task %s not exists: %s",
                      task.name, output_file)
        passed = False

        info.result = options.TaskResult.failed
        info.error_message = "Hap not found"
        return passed
    try:
        with zipfile.ZipFile(output_file, 'r') as zip_ref:
            zip_ref.extractall(uncompressed_output_file)
    except Exception as e:
        logging.error(f"unzip exception: {e}")
        logging.error(
            f"uncompressed output file for task {task.name} failed. output file: {output_file}")
        passed = False

        info.result = options.TaskResult.failed
        info.error_message = "Hap uncompressed failed, cannot exam build products"
        return passed

    if utils.is_esmodule(task.type):
        passed = validate_output_for_esmodule(
            info, task, uncompressed_output_file, is_debug)
    else:
        passed = validate_output_for_jsbundle(
            info, task, uncompressed_output_file, is_debug)

    shutil.rmtree(uncompressed_output_file)

    return passed


def run_compile_output(info, task_path):
    # TODO:
    # 1)install hap
    # 2)run hap and verify
    return False


def is_compile_success(compile_stdout):
    pattern = r"BUILD SUCCESSFUL in (\d+ min )?(\d+ s )?(\d+ ms)?"
    match_result = re.search(pattern, compile_stdout)
    if not match_result:
        return [False, '']

    return [True, match_result.group(0)]


def validate(compilation_info, task, is_debug, stdout, stderr, output_file=''):
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
        return False

    passed = validate_compile_output(info, task, is_debug, output_file)

    if options.arguments.run_haps:
        passed &= run_compile_output(info)

    if passed:
        collect_compile_time(info, time_string)
        info.result = options.TaskResult.passed

    return passed


def get_hvigor_path(project_path):
    hvigor = ''
    if utils.is_windows():
        hvigor = os.path.join(project_path, 'hvigorw.bat')
    else:
        hvigor = os.path.join(project_path, 'hvigorw')
        utils.add_executable_permission(hvigor)
    return hvigor


def get_hvigor_compile_cmd(project_path, is_debug):
    cmd = [get_hvigor_path(project_path)]
    if is_debug:
        cmd.append('assembleHap')
    else:
        cmd.append('assembleApp')
    return cmd


def compile_project(task, is_debug, cmd=''):
    if not cmd:
        cmd = get_hvigor_compile_cmd(task.path, is_debug)

    logging.debug(f'cmd: {cmd}')
    logging.debug(f"cmd execution path {task.path}")
    process = subprocess.Popen(cmd, shell=False, cwd=task.path,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(
        timeout=options.arguments.compile_timeout)
    stdout_utf8 = stdout.decode("utf-8", errors="ignore")
    stderr_utf8 = stderr.decode("utf-8", errors="ignore")
    logging.debug(f"cmd stdout: {stdout_utf8}")
    logging.debug(f"cmd stderr: {stderr_utf8}")

    return [stdout_utf8, stderr_utf8]


def clean_compile(task):
    cmd = [get_hvigor_path(task.path), 'clean']
    logging.debug(f'cmd: {cmd}')
    logging.debug(f"cmd execution path {task.path}")
    process = subprocess.Popen(cmd, shell=False, cwd=task.path,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate(timeout=options.arguments.compile_timeout)


def compile_incremental(task, is_debug):
    logging.info(
        f"==========> Running task: {task.name} in incremental compilation")
    [stdout, stderr] = compile_project(task, is_debug)

    [is_success, time_string] = is_compile_success(stdout)
    if not is_success:
        logging.error(
            "Incremental compile failed due to first compile failed!")
        return

    if options.arguments.compile_mode == 'incremental':
        passed = validate(task.full_compilation_info,
                          task, is_debug, stdout, stderr)
        if not passed:
            logging.error(
                "Incremental compile failed due to first compile failed!")
            return

    backup_compile_output(task, is_debug)
    backup_compile_cache(task, is_debug)

    IncrementalTest.compile_incremental_no_modify(task, is_debug)
    IncrementalTest.compile_incremental_add_oneline(task, is_debug)
    IncrementalTest.compile_incremental_add_file(task, is_debug)
    IncrementalTest.compile_incremental_delete_file(task, is_debug)
    IncrementalTest.compile_incremental_reverse_hap_mode(task, is_debug)
    IncrementalTest.compile_incremental_modify_module_name(task, is_debug)


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
    backup_output = os.path.join(
        backup_output_path, os.path.basename(output_file))
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
    cache_files = os.path.join(
        task.path, *(task.build_path), *(task.cache_path))

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


def execute_full_compile(task):
    logging.info(f"==========> Running task: {task.name} in full compilation")
    clean_compile(task)
    passed = False
    if options.arguments.hap_mode in ['all', 'release']:
        [stdout, stderr] = compile_project(task, False)
        passed = validate(task.full_compilation_info,
                          task, False, stdout, stderr)
        if passed:
            backup_compile_output(task, False)
        clean_compile(task)
    if options.arguments.hap_mode in ['all', 'debug']:
        [stdout, stderr] = compile_project(task, True)
        passed = validate(task.full_compilation_info,
                          task, True, stdout, stderr)
        if passed:
            backup_compile_output(task, True)
        clean_compile(task)

    return passed


def execute_incremental_compile(task):
    logging.info(
        f"==========> Running task: {task.name} in incremental compilation")
    if options.arguments.hap_mode in ['all', 'release']:
        compile_incremental(task, False)
        clean_compile(task)
    if options.arguments.hap_mode in ['all', 'debug']:
        compile_incremental(task, True)
        clean_compile(task)


def clean_backup(task):
    if os.path.exists(task.backup_info.cache_path):
        shutil.rmtree(task.backup_info.cache_path)
    return


def execute(test_tasks):
    for task in test_tasks:
        try:
            logging.info(f"======> Running task: {task.name}")
            if options.arguments.compile_mode in ['all', 'full']:
                if not execute_full_compile(task):
                    logging.info("Full compile failed, skip other tests!")
                    continue

            if options.arguments.compile_mode in ['all', 'incremental']:
                execute_incremental_compile(task)

            OtherTest.verify_binary_consistency(task)

            # for these tests, use one hapMode maybe enough
            is_debug = True if options.arguments.hap_mode == 'debug' else False
            OtherTest.execute_break_compile(task, is_debug)
            if 'error' in task.type:
                OtherTest.compile_full_with_error(task, is_debug)

            if 'exceed_length_error' in task.type:
                OtherTest.compile_with_exceed_length(task, is_debug)

            if 'ohosTest' in task.type:
                OtherTest.compile_ohos_test(task)

            logging.info(f"======> Running task: {task.name} finised")
        except Exception as e:
            logging.exception(e)
        finally:
            clean_backup(task)
