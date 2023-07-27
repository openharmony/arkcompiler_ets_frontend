#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Huawei Device Co., Ltd.
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


import logging
import os
import subprocess
import stat
import sys
import time
import zipfile

import json5

import performance_config


class PerformanceBuild():
    def __init__(self, config_input, mail_obj):
        self.config = None
        self.first_line_in_avg_excel = ""
        self.time_avg_dic = {}
        self.all_time_dic = {}
        self.size_avg_dic = {}
        self.all_size_dic = {}
        self.mail_helper = None
        self.mail_msg = ''
        self.developing_test_mode = False
        self.mail_helper = mail_obj
        self.config = config_input
        self.prj_name = ''
        self.timeout = 180

    def start(self):
        self.init()
        self.start_test()
        self.write_mail_msg()
        os.chdir(self.config.project_path)

    @staticmethod
    def append_into_dic(key, value, dic):
        if key not in dic:
            dic[key] = []
        dic[key].append(value)

    def init(self):
        self.developing_test_mode = self.config.developing_test_mode
        if self.config.ide == performance_config.IdeType.DevEco:
            os.environ['path'] = self.config.node_js_path + ";" + os.environ['path']
        os.chdir(self.config.project_path)
        os.environ['path'] = os.path.join(self.config.jbr_path, "bin") + ";" + os.environ['path']
        os.environ['JAVA_HOME'] = self.config.jbr_path
        self.config.cmd_prefix = os.path.join(self.config.project_path, self.config.cmd_prefix)
        self.config.log_direct = os.path.join(self.config.project_path, self.config.log_direct)
        self.config.debug_package_path = os.path.join(self.config.project_path, self.config.debug_package_path)
        self.config.release_package_path = os.path.join(self.config.project_path, self.config.release_package_path)
        self.config.incremental_code_path = os.path.join(self.config.project_path, self.config.incremental_code_path)
        self.config.json5_path = os.path.join(self.config.project_path, self.config.json5_path)
        if not os.path.exists(self.config.log_direct):
            os.makedirs(self.config.log_direct)
        self.config.log_direct = os.path.join(self.config.log_direct,
                                        time.strftime(self.config.log_direct_data_format,
                                        time.localtime()))
        if not os.path.exists(self.config.log_direct):
            os.makedirs(self.config.log_direct)
        self.config.log_direct = os.path.join(self.config.project_path, self.config.log_direct)
        self.config.error_filename = os.path.join(self.config.log_direct, self.config.error_filename)
        logging.basicConfig(filename=self.config.error_filename,
                            format='[%(asctime)s %(filename)s:%(lineno)d]: [%(levelname)s] %(message)s')
        if self.developing_test_mode:
            self.config.build_times = 3

    @staticmethod
    def add_code(code_path, start_pos, end_pos, code_str, lines):
        with open(code_path, 'r+', encoding='UTF-8') as modified_file:
            content = modified_file.read()
            add_str_end_pos = content.find(end_pos)
            if add_str_end_pos == -1:
                print('Can not find code : {end_pos} in {code_path}, please check config')
                return
            add_str_start_pos = content.find(start_pos)
            if add_str_start_pos == -1:
                if lines == 0:
                    return
                add_str_start_pos = add_str_end_pos
            content_add = ""
            for i in range(lines, 0, -1):
                if "%d" in code_str:
                    content_add = content_add + code_str % i
                else:
                    content_add = content_add + code_str
            content = content[:add_str_start_pos] + content_add + content[add_str_end_pos:]
            modified_file.seek(0)
            modified_file.write(content)
            modified_file.truncate()

    def add_incremental_code(self, lines):
        PerformanceBuild.add_code(self.config.incremental_code_path,
                self.config.incremental_code_start_pos,
                self.config.incremental_code_end_pos,
                self.config.incremental_code_str,
                lines)

    def revert_incremental_code(self):
        self.add_incremental_code(0)

    def reset(self):
        self.first_line_in_avg_excel = ""
        self.time_avg_dic = {}
        self.all_time_dic = {}
        self.size_avg_dic = {}
        self.all_size_dic = {}
        self.revert_incremental_code()

    def clean_project(self):
        if not self.developing_test_mode:
            print(self.config.cmd_prefix + " clean --no-daemon")
            subprocess.Popen((self.config.cmd_prefix + " clean --no-daemon").split(" "),
                             stderr=sys.stderr,
                             stdout=sys.stdout).communicate(timeout=self.timeout)

    def get_bytecode_size(self, is_debug):
        if self.developing_test_mode:
            # test data for size
            PerformanceBuild.append_into_dic("ets/mudules.abc rawSize", 44444, self.all_size_dic)
            PerformanceBuild.append_into_dic("ets/mudules.abc Compress_size", 33333, self.all_size_dic)
            PerformanceBuild.append_into_dic("ets/mudules2.abc rawSize", 44444, self.all_size_dic)
            PerformanceBuild.append_into_dic("ets/mudules2.abc Compress_size", 33333, self.all_size_dic)
            return
        package_path = self.config.debug_package_path if is_debug else self.config.release_package_path
        package = zipfile.ZipFile(package_path)
        extension_name = ".abc" if self.config.ide == performance_config.IdeType.DevEco else ".dex"
        for info in package.infolist():
            if info.filename.endswith(extension_name):
                name_str1 = info.filename + " rawSize"
                name_str2 = info.filename + " compress_size"
                PerformanceBuild.append_into_dic(name_str1, info.file_size, self.all_size_dic)
                PerformanceBuild.append_into_dic(name_str2, info.compress_size, self.all_size_dic)

    def start_build(self, is_debug):
        if self.developing_test_mode:
            # test data
            PerformanceBuild.append_into_dic("task1", 6800, self.all_time_dic)
            PerformanceBuild.append_into_dic("task2", 3200, self.all_time_dic)
            PerformanceBuild.append_into_dic("total build cost", 15200, self.all_time_dic)
            return True
        cmd_suffix = self.config.cmd_debug_suffix if is_debug else self.config.cmd_release_suffix
        print(self.config.cmd_prefix + cmd_suffix)
        p = subprocess.Popen((self.config.cmd_prefix + cmd_suffix).split(" "),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
        while True:
            log_str = p.stdout.readline().decode('utf-8')
            if not log_str:
                break
            print(log_str, end='')
            cost_time = 0
            str_finished = "Finished :"
            if str_finished in log_str:
                name_start_pos = log_str.find(str_finished) + len(str_finished)
                name_end_pos = log_str.find('...')
                key_str = log_str[name_start_pos:name_end_pos]
                cost_time = self.get_millisecond(log_str.split(' after ')[1])
            elif 'BUILD SUCCESSFUL' in log_str:
                key_str = 'total build cost'
                cost_time = self.get_millisecond(log_str.split(' in ')[1])
            elif 'ERROR' in log_str:
                rest_error = p.stdout.read().decode('utf-8')
                print(rest_error)
                log_str += rest_error
                logging.error(log_str)
                p.communicate(timeout=self.timeout)
                return False
            else:
                continue
            PerformanceBuild.append_into_dic(key_str, cost_time, self.all_time_dic)
        p.communicate(timeout=self.timeout)
        return True
        

    def get_millisecond(self, time_string):
        if self.config.ide != performance_config.IdeType.DevEco and not self.developing_test_mode:
            return int(time_string)
        else:
            cost_time = 0
            res = time_string.split(" min ")
            target_str = ""
            if len(res) > 1:
                cost_time = int(res[0]) * 60000
                target_str = res[1]
            else:
                target_str = res[0]
            res = target_str.split(" s ")
            if len(res) > 1:
                cost_time = cost_time + int(res[0]) * 1000
                target_str = res[1]
            else:
                target_str = res[0]
            
            res = target_str.split(" ms")
            if len(res) > 1:
                cost_time = cost_time + int(res[0])
            return cost_time
        
    def cal_incremental_avg_time(self):
        self.first_line_in_avg_excel = self.first_line_in_avg_excel + "\n"
        for key in self.all_time_dic:
            task_count = len(self.all_time_dic[key])
            has_task = True
            if task_count != 2 * self.config.build_times:
                if task_count == self.config.build_times:
                    has_task = False
                else:
                    continue
            # average of first build
            sum_build_time = 0
            for i in range(0, self.config.build_times):
                index = i * 2
                if not has_task:
                    self.all_time_dic[key].insert(index + 1, 0)
                sum_build_time = sum_build_time + self.all_time_dic[key][index]
            cost = "%.2f s" % (sum_build_time / self.config.build_times / 1000)
            PerformanceBuild.append_into_dic(key, cost, self.time_avg_dic)
            # average of incremental build
            sum_build_time = 0
            for i in range(1, len(self.all_time_dic[key]), 2):
                sum_build_time = sum_build_time + self.all_time_dic[key][i]
            cost = "%.2f s" % (sum_build_time / self.config.build_times / 1000)
            PerformanceBuild.append_into_dic(key, cost, self.time_avg_dic)

    def cal_incremental_avg_size(self):
        total_raw_size = []
        total_compressed_size = []
        for i in range(0, self.config.build_times * 2):
            total_raw_size.append(0)
            total_compressed_size.append(0)
            for key in self.all_size_dic:
                if "raw" in key:
                    total_raw_size[i] += self.all_size_dic[key][i]
                else:
                    total_compressed_size[i] += self.all_size_dic[key][i]
        self.all_size_dic["total_raw_size"] = total_raw_size
        self.all_size_dic["total_compressed_size"] = total_compressed_size
        for key in self.all_size_dic:
            # sizes should be the same, just check
            is_size_the_same = True
            full_first_size = self.all_size_dic[key][0]
            for i in range(0, len(self.all_size_dic[key]), 2):
                if full_first_size != self.all_size_dic[key][i]:
                    is_size_the_same = False
                    break
            is_size_the_same = is_size_the_same and full_first_size != -1
            full_avg_size = f"{full_first_size} Byte" if is_size_the_same else "size is not the same"
            PerformanceBuild.append_into_dic(key, full_avg_size, self.size_avg_dic)

            is_size_the_same = True
            incremental_first_size = self.all_size_dic[key][1]
            for i in range(1, len(self.all_size_dic[key]), 2):
                if incremental_first_size != self.all_size_dic[key][i]:
                    is_size_the_same = False
                    break
            is_size_the_same = is_size_the_same and incremental_first_size != -1
            incremental_avg_size = f"{incremental_first_size} Byte" if is_size_the_same else "size is not the same"
            PerformanceBuild.append_into_dic(key, incremental_avg_size, self.size_avg_dic)

    def cal_incremental_avg(self):
        self.cal_incremental_avg_time()
        self.cal_incremental_avg_size()

    @staticmethod
    def add_row(context):
        return rf'<tr align="center">{context}</tr>'

    @staticmethod
    def add_td(context):
        return rf'<td>{context}</td>'

    @staticmethod
    def add_th(context):
        return rf'<th  width="30%">{context}</th>'

    @staticmethod
    def test_type_title(context):
        return rf'<tr><th bgcolor="PaleGoldenRod" align="center" colspan="3">{context}</th></tr>'

    @staticmethod
    def app_title(context):
        return rf'<th bgcolor="SkyBlue" colspan="3"><font size="4">{context}</font></th>'
    
    def add_time_pic_data(self, dic, is_debug):
        for key in dic:
            full_time = dic[key][0]
            full_time = float(full_time[:len(full_time) - 2])
            incremental_time = dic[key][1]
            incremental_time = float(incremental_time[:len(incremental_time) - 2])
        self.mail_helper.add_pic_data(self.prj_name, is_debug, [full_time, incremental_time])

    def add_size_pic_data(self, dic, is_debug):
        for key in dic:
            full_size = dic[key][0]
            full_size = float(full_size[:len(full_size) - 5])
        self.mail_helper.add_pic_data(self.prj_name, is_debug, [full_size])
    
    @staticmethod
    def write_mail_files(first_line, dic, mail_table_title="", is_debug=""):
        msg = PerformanceBuild.test_type_title(mail_table_title)
        if first_line:
            first_row = ""
            first_line_res = first_line.replace("\n", "").split(",")
            for i in first_line_res:
                first_row += PerformanceBuild.add_th(i)
            rows = PerformanceBuild.add_row(first_row)
        
        for key in dic:
            content_row = PerformanceBuild.add_th(key)
            if "total" in key:
                for v in dic[key]:
                    content_row += PerformanceBuild.add_td(v)
                rows += PerformanceBuild.add_row(content_row)
        msg += rows
        return msg

    def write_from_dic(self, file_path, first_line, dic):
        content_list = []
        if first_line:
            content_list.append(first_line)
        for key in dic:
            content_list.append(key)
            for v in dic[key]:
                content_list.append(",")
                content_list.append(str(v))
            content_list.append("\n")
        excel_path = os.path.join(self.config.log_direct, os.path.basename(file_path))
        content = "".join(content_list)
        with os.fdopen(os.open(excel_path,
                               os.O_WRONLY | os.O_CREAT,
                               stat.S_IRWXU | stat.S_IRWXO | stat.S_IRWXG), 'w') as excel:
            excel.write(content)
            self.mail_helper.add_logs_file(file_path, content.encode())


    def generate_full_and_incremental_results(self, is_debug, aot_mode):
        path_prefix = self.config.output_split.join(
            (self.config.ide_filename[self.config.ide - 1],
            self.config.debug_or_release[0 if is_debug else 1],
            self.config.aot_mode[aot_mode],
            self.config.build_type_of_log[0])
        )
        temp_mail_msg = ""
        # sizeAll
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[0]))
        file_path = os.path.join(self.prj_name, file_path)
        self.write_from_dic(file_path, None, self.all_size_dic)
        # sizeAvg and mailmsg
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[1]))
        file_path = os.path.join(self.prj_name, file_path)
        self.write_from_dic(file_path, self.first_line_in_avg_excel, self.size_avg_dic)
        temp_mail_msg += PerformanceBuild.write_mail_files(self.first_line_in_avg_excel,
                                                           self.size_avg_dic, 'abc Size')
        self.add_size_pic_data(self.size_avg_dic, is_debug)
        # timeAll
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[2]))
        file_path = os.path.join(self.prj_name, file_path)
        self.write_from_dic(file_path, None, self.all_time_dic)
        # timeAvg and mailmsg
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[3]))
        file_path = os.path.join(self.prj_name, file_path)
        self.write_from_dic(file_path, self.first_line_in_avg_excel, self.time_avg_dic)
        temp_mail_msg += PerformanceBuild.write_mail_files(self.first_line_in_avg_excel,
                                                           self.time_avg_dic, 'Build Time', is_debug)
        self.add_time_pic_data(self.time_avg_dic, is_debug)
        # mail files
        if self.config.send_mail:
            temp_mail_msg = '<table width="100%" border=1 cellspacing=0 cellpadding=0 align="center">' + \
                PerformanceBuild.app_title(self.prj_name + (' Debug' if is_debug else ' Release')) + \
                temp_mail_msg + '</table>'
            self.mail_msg += temp_mail_msg

    def set_aot_mode(self, aot_mode):
        with open(self.config.json5_path, 'r+', encoding='UTF-8') as modified_file:
            json_obj = json5.load(modified_file)
            opt_obj = json_obj.get("buildOption")
            if not opt_obj:
                opt_obj = {}
                json_obj["buildOption"] = opt_obj
            compile_mode = opt_obj.get("aotCompileMode")
            if aot_mode == performance_config.AotMode.Type:
                if compile_mode == 'type':
                    return
                else:
                    opt_obj["aotCompileMode"] = 'type'
            else:
                if not compile_mode:
                    return
                else:
                    del opt_obj["aotCompileMode"]
            modified_file.seek(0)
            json5.dump(json_obj, modified_file, indent=4)
            modified_file.truncate()


    def error_handle(self, is_debug, log_type, aot_mode):
        build_mode = performance_config.BuildMode.DEBUG if is_debug else performance_config.BuildMode.RELEASE
        if log_type == performance_config.LogType.FULL:
            self.mail_helper.add_failed_project(self.prj_name, build_mode,
                                                performance_config.LogType.FULL, aot_mode)
        self.mail_helper.add_failed_project(self.prj_name, build_mode,
                                            performance_config.LogType.INCREMENTAL, aot_mode)
        if os.path.exists(self.config.error_filename):
            with open(self.config.error_filename, 'r') as error_log:
                save_name = os.path.basename(self.config.error_filename)
                self.mail_helper.add_logs_file(os.path.join(self.prj_name, save_name),
                                               error_log.read())

    def full_and_incremental_build(self, is_debug, aot_mode):
        self.reset()
        self.set_aot_mode(aot_mode)
        self.prj_name = self.mail_helper.get_project_name(
            os.path.basename(self.config.project_path),
            aot_mode
        )
        if self.developing_test_mode:
            PerformanceBuild.append_into_dic("task0", 7100, self.all_time_dic)
        self.first_line_in_avg_excel = self.first_line_in_avg_excel + ",first build,incremental build"
        for i in range(self.config.build_times):
            self.clean_project()
            print(f"fullbuild: is_debug{is_debug}, aot_mode:{aot_mode == performance_config.AotMode.Type}")
            res = self.start_build(is_debug)
            if not res:
                self.error_handle(is_debug, performance_config.LogType.FULL, aot_mode)
                return res
            self.get_bytecode_size(is_debug)
            self.add_incremental_code(1)
            print(f"incremental: is_debug{is_debug}, aot_mode:{aot_mode == performance_config.AotMode.Type}")
            res = self.start_build(is_debug)
            if not res:
                self.error_handle(is_debug, performance_config.LogType.INCREMENTAL, aot_mode)
                return res
            self.get_bytecode_size(is_debug)
            self.revert_incremental_code()
        self.cal_incremental_avg()
        self.generate_full_and_incremental_results(is_debug, aot_mode)
        return True

    def start_test(self):
        self.full_and_incremental_build(True, performance_config.AotMode.NoAOT)
        self.full_and_incremental_build(False, performance_config.AotMode.NoAOT)
        self.full_and_incremental_build(True, performance_config.AotMode.Type)
        self.full_and_incremental_build(False, performance_config.AotMode.Type)
        self.set_aot_mode(performance_config.AotMode.NoAOT)

    def write_mail_msg(self):
        if self.config.send_mail:
            self.mail_helper.add_msg(self.mail_msg)


def run(config_input, mail_obj):
    start_time = time.time()
    PerformanceBuild(config_input, mail_obj).start()
    print("Test [%s] finished at: %s\n"\
        "total cost: %ds"
        % (os.path.basename(config_input.project_path),
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            time.time() - start_time))