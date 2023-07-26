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


import os
import subprocess
import stat
import time
import zipfile

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
        self.built_times = 0
        self.mail_msg = ''
        # If developing_test_mode is True, the project will not be built and use following test data
        self.developing_test_mode = False
        self.developing_test_data = 'entry:clean|18 ms 	:clean|1 ms 	total build cost|1 s 204 ms 	' + \
        'entry:default@OneTime|1 s 204 ms 	' + \
        'entry:default@MergeProfile|4 ms 	entry:default@BuildNativeWithCmake|1 ms 	' + \
        'entry:default@GenerateLoaderJson|2 ms 	entry:default@MakePackInfo|8 ms 	' + \
        'entry:default@ProcessProfile|85 ms 	entry:default@BuildNativeWithNinja|1 ms 	' + \
        'entry:default@ProcessResource|2 ms 	entry:default@ProcessLibs|3 ms 	entry:default@CompileResource|78 ms 	' + \
        'entry:default@CompileJS|2 ms 	entry:default@CompileArkTS|2 s 591 ms 	entry:default@PackageHap|924 ms 	' + \
        'entry:default@SignHap|2 ms 	entry:assembleHap|1 ms 	total build cost|4 s 886 ms 	' + \
        'entry:default@BuildNativeWithCmake|1 ms 	entry:default@BuildNativeWithNinja|1 ms 	' + \
        'entry:default@CompileJS|4 ms 	entry:default@CompileArkTS|2 s 472 ms 	entry:default@PackageHap|919 ms 	' + \
        'entry:assembleHap|1 ms 	entry:default@SignHap|2 ms 	total build cost|4 s 632 ms 	' + \
        'entry:clean|18 ms 	:clean|1 ms 	total build cost|1 s 204 ms 	entry:default@MergeProfile|4 ms 	' + \
        'entry:default@BuildNativeWithCmake|1 ms 	entry:default@GenerateLoaderJson|2 ms 	' + \
        'entry:default@MakePackInfo|8 ms 	entry:default@ProcessProfile|85 ms 	' + \
        'entry:default@BuildNativeWithNinja|1 ms 	entry:default@ProcessResource|2 ms 	' + \
        'entry:default@ProcessLibs|3 ms 	entry:default@CompileResource|78 ms 	entry:default@CompileJS|2 ms 	' + \
        'entry:default@CompileArkTS|2 s 591 ms 	entry:default@PackageHap|924 ms 	entry:default@SignHap|2 ms 	' + \
        'entry:assembleHap|1 ms 	total build cost|4 s 886 ms 	entry:default@BuildNativeWithCmake|1 ms 	' + \
        'entry:default@BuildNativeWithNinja|1 ms 	entry:default@CompileJS|4 ms 	' + \
        'entry:default@CompileArkTS|2 s 472 ms 	entry:default@PackageHap|919 ms 	entry:default@SignHap|2 ms 	' + \
        'entry:assembleHap|1 ms 	total build cost|4 s 632 ms 	entry:clean|18 ms 	:clean|1 ms 	' + \
        'total build cost|1 s 204 ms 	entry:default@MergeProfile|4 ms 	entry:default@BuildNativeWithCmake|1 ms' + \
        ' 	entry:default@GenerateLoaderJson|2 ms 	entry:default@MakePackInfo|8 ms 	' + \
        'entry:default@ProcessProfile|85 ms 	entry:default@BuildNativeWithNinja|1 ms' + \
        ' 	entry:default@ProcessResource|2 ms 	entry:default@ProcessLibs|3 ms 	entry:default@CompileResource|78 ms' + \
        ' 	entry:default@CompileJS|2 ms 	entry:default@CompileArkTS|2 s 591 ms 	' + \
        'entry:default@PackageHap|924 ms 	entry:default@SignHap|2 ms 	entry:assembleHap|1 ms 	' + \
        'total build cost|4 s 886 ms 	entry:default@BuildNativeWithCmake|1 ms 	' + \
        'entry:default@BuildNativeWithNinja|1 ms 	entry:default@CompileJS|4 ms 	' + \
        'entry:default@CompileArkTS|2 s 472 ms 	entry:default@PackageHap|919 ms 	entry:default@SignHap|2 ms 	' + \
        'entry:assembleHap|1 ms 	total build cost|4 s 632 ms 	'
        self.mail_helper = mail_obj
        self.config = config_input

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
        self.config.temp_filename = os.path.join(self.config.log_direct, self.config.temp_filename)
        self.config.debug_package_path = os.path.join(self.config.project_path, self.config.debug_package_path)
        self.config.release_package_path = os.path.join(self.config.project_path, self.config.release_package_path)
        self.config.incremental_code_path = os.path.join(self.config.project_path, self.config.incremental_code_path)
        if not os.path.exists(self.config.log_direct):
            os.makedirs(self.config.log_direct)
        self.config.log_direct = os.path.join(self.config.log_direct,
                                        time.strftime(self.config.log_direct_data_format,
                                        time.localtime()))
        if not os.path.exists(self.config.log_direct):
            os.makedirs(self.config.log_direct)
        self.config.log_direct = os.path.join(self.config.project_path, self.config.log_direct)
        if self.developing_test_mode:
            self.config.build_times = 3

    def clean_temp_log(self):
        if os.path.exists(self.config.temp_filename):
            os.remove(self.config.temp_filename)

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
        self.built_times = 0
        self.clean_temp_log()
        self.revert_incremental_code()

    def clean_project(self):
        if not self.developing_test_mode:
            print(self.config.cmd_prefix + " clean --no-daemon")
            subprocess.Popen(self.config.cmd_prefix + " clean --no-daemon").wait()

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
            return
        cmd_suffix = self.config.cmd_debug_suffix if is_debug else self.config.cmd_release_suffix
        print(self.config.cmd_prefix + cmd_suffix)
        subprocess.Popen(self.config.cmd_prefix + cmd_suffix).wait()

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
        content = ""
        if self.developing_test_mode:
            content = self.developing_test_data.split("\t")
        else:
            with open(self.config.temp_filename, "r", encoding='UTF-8') as src:
                content = src.read().split("\t")
        clean_filter = False
        for task_build_time_str in content:
            if len(task_build_time_str) == 0:
                continue
            pair = task_build_time_str.split("|")
            key_str = pair[0]
            if clean_filter:
                if "total" in key_str:
                    clean_filter = False
                continue
            if "clean" in key_str:
                clean_filter = True
                continue
            cost_time = self.get_millisecond(pair[1])
            PerformanceBuild.append_into_dic(key_str, cost_time, self.all_time_dic)
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
        self.clean_temp_log()

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
    
    def write_mail_files(self, file_path, first_line, dic, mail_table_title="", is_debug=""):
        msg = PerformanceBuild.test_type_title(mail_table_title)
        if first_line:
            first_row = ""
            first_line_res = first_line.replace("\n", "").split("\t")
            for i in first_line_res:
                first_row += PerformanceBuild.add_th(i)
            rows = PerformanceBuild.add_row(first_row)
        
        for key in dic:
            content_row = PerformanceBuild.add_th(key)
            if "total" in key:
                for v in dic[key]:
                    content_row += PerformanceBuild.add_td(v)
                rows += PerformanceBuild.add_row(content_row)
                if is_debug != '':
                    full_time = dic[key][0]
                    full_time = float(full_time[:len(full_time) - 2])
                    incremental_time = dic[key][1]
                    incremental_time = float(incremental_time[:len(incremental_time) - 2])
                    self.mail_helper.add_pic_data(is_debug, [full_time, incremental_time])
        msg += rows
        return msg

    def write_from_dic(self, file_path, first_line, dic, mail_table_title="", is_debug=""):
        content_list = []
        if first_line:
            content_list.append(first_line)
        for key in dic:
            content_list.append(key)
            for v in dic[key]:
                content_list.append("\t")
                content_list.append(str(v))
            content_list.append("\n")
        excel_path = os.path.join(self.config.log_direct, os.path.basename(file_path))
        content = "".join(content_list)
        with os.fdopen(os.open(excel_path,
                               os.O_WRONLY | os.O_CREAT,
                               stat.S_IRWXU | stat.S_IRWXO | stat.S_IRWXG), 'w') as excel:
            excel.write(content)
            self.mail_helper.add_logs_file(file_path, content.encode())
        
        if mail_table_title:
            return self.write_mail_files(file_path, first_line, dic, mail_table_title, is_debug)
        else:
            return ""

    def generate_full_and_incremental_results(self, is_debug):
        path_prefix = self.config.output_split.join(
            (self.config.ide_filename[self.config.ide - 1],
            self.config.debug_or_release[0 if is_debug else 1],
            self.config.build_type_of_log[0])
        )
        prj_name = os.path.basename(self.config.project_path)
        temp_mail_msg = ""
        # sizeAll
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[0]))
        file_path = os.path.join(prj_name, file_path)
        self.write_from_dic(file_path, None, self.all_size_dic)
        # sizeAvg and mailmsg
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[1]))
        file_path = os.path.join(prj_name, file_path)
        temp_mail_msg += self.write_from_dic(file_path, self.first_line_in_avg_excel, self.size_avg_dic, "Size")
        # timeAll
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[2]))
        file_path = os.path.join(prj_name, file_path)
        self.write_from_dic(file_path, None, self.all_time_dic)
        # timeAvg and mailmsg
        file_path = self.config.output_split.join((path_prefix, self.config.log_filename[3]))
        file_path = os.path.join(prj_name, file_path)
        temp_mail_msg += self.write_from_dic(file_path, self.first_line_in_avg_excel,
                                             self.time_avg_dic, "Time", is_debug)
        # mail files
        if self.config.send_mail:
            temp_mail_msg = '<table width="100%" border=1 cellspacing=0 cellpadding=0 align="center">' + \
                PerformanceBuild.app_title(prj_name + (' Debug' if is_debug else ' Release')) + \
                temp_mail_msg + '</table>'
            self.mail_msg += temp_mail_msg

    def full_and_incremental_build(self, is_debug):
        self.reset()
        self.first_line_in_avg_excel = self.first_line_in_avg_excel + "\tfirst build\tincremental build"
        for i in range(self.config.build_times):
            self.clean_project()
            self.start_build(is_debug)
            self.get_bytecode_size(is_debug)
            self.add_incremental_code(1)
            self.start_build(is_debug)
            self.get_bytecode_size(is_debug)
            self.revert_incremental_code()
        self.cal_incremental_avg()
        self.generate_full_and_incremental_results(is_debug)

    def start_test(self):
        self.full_and_incremental_build(True)
        self.full_and_incremental_build(False)

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