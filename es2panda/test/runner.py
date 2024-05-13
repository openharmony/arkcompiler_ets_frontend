#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

from glob import glob
from os import path
from enum import Enum
import argparse
import fnmatch
import multiprocessing
import os
import re
import shutil
import subprocess
import sys


def is_directory(parser, arg):
    if not path.isdir(arg):
        parser.error("The directory '%s' does not exist" % arg)

    return path.abspath(arg)


def is_file(parser, arg):
    if not path.isfile(arg):
        parser.error("The file '%s' does not exist" % arg)

    return path.abspath(arg)

def prepare_tsc_testcases(test_root):
    third_party_tsc = path.join(test_root, "TypeScript")
    ohos_third_party_tsc = path.join(test_root, "../../../../third_party/typescript")

    if not path.isdir(third_party_tsc):
        if (path.isdir(ohos_third_party_tsc)):
            return path.abspath(ohos_third_party_tsc)
        subprocess.run(
            f"git clone https://gitee.com/openharmony/third_party_typescript.git {third_party_tsc}",
            shell=True,
            stdout=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            f"cd {third_party_tsc} && git clean -f > /dev/null 2>&1",
            shell=True,
            stdout=subprocess.DEVNULL,
        )
    return third_party_tsc

def check_timeout(value):
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(
            "%s is an invalid timeout value" % value)
    return ivalue


def get_args():
    parser = argparse.ArgumentParser(description="Regression test runner")
    parser.add_argument(
        'build_dir', type=lambda arg: is_directory(parser, arg),
        help='panda build directory')
    parser.add_argument(
        '--error', action='store_true', dest='error', default=False,
        help='capture stderr')
    parser.add_argument(
        '--abc-to-asm', action='store_true', dest='abc_to_asm',
        default=False, help='run abc2asm tests')
    parser.add_argument(
        '--regression', '-r', action='store_true', dest='regression',
        default=False, help='run regression tests')
    parser.add_argument(
        '--compiler', '-c', action='store_true', dest='compiler',
        default=False, help='run compiler tests')
    parser.add_argument(
        '--tsc', action='store_true', dest='tsc',
        default=False, help='run tsc tests')
    parser.add_argument(
        '--no-progress', action='store_false', dest='progress', default=True,
        help='don\'t show progress bar')
    parser.add_argument(
        '--no-skip', action='store_false', dest='skip', default=True,
        help='don\'t use skiplists')
    parser.add_argument(
        '--update', action='store_true', dest='update', default=False,
        help='update skiplist')
    parser.add_argument(
        '--no-run-gc-in-place', action='store_true', dest='no_gip', default=False,
        help='enable --run-gc-in-place mode')
    parser.add_argument(
        '--filter', '-f', action='store', dest='filter',
        default="*", help='test filter regexp')
    parser.add_argument(
        '--es2panda-timeout', type=check_timeout,
        dest='es2panda_timeout', default=60, help='es2panda translator timeout')
    parser.add_argument(
        '--paoc-timeout', type=check_timeout,
        dest='paoc_timeout', default=600, help='paoc compiler timeout')
    parser.add_argument(
        '--timeout', type=check_timeout,
        dest='timeout', default=10, help='JS runtime timeout')
    parser.add_argument(
        '--gc-type', dest='gc_type', default="g1-gc", help='Type of garbage collector')
    parser.add_argument(
        '--aot', action='store_true', dest='aot', default=False,
        help='use AOT compilation')
    parser.add_argument(
        '--no-bco', action='store_false', dest='bco', default=True,
        help='disable bytecodeopt')
    parser.add_argument(
        '--jit', action='store_true', dest='jit', default=False,
        help='use JIT in interpreter')
    parser.add_argument(
        '--arm64-compiler-skip', action='store_true', dest='arm64_compiler_skip', default=False,
        help='use skiplist for tests failing on aarch64 in AOT or JIT mode')
    parser.add_argument(
        '--arm64-qemu', action='store_true', dest='arm64_qemu', default=False,
        help='launch all binaries in qemu aarch64')
    parser.add_argument(
        '--arm32-qemu', action='store_true', dest='arm32_qemu', default=False,
        help='launch all binaries in qemu arm')
    parser.add_argument(
        '--test-list', dest='test_list', default=None, type=lambda arg: is_file(parser, arg),
        help='run tests listed in file')
    parser.add_argument(
        '--aot-args', action='append', dest='aot_args', default=[],
        help='Additional arguments that will passed to ark_aot')
    parser.add_argument(
        '--verbose', '-v', action='store_true', dest='verbose', default=False,
        help='Enable verbose output')
    parser.add_argument(
        '--js-runtime', dest='js_runtime_path', default=None, type=lambda arg: is_directory(parser, arg),
        help='the path of js vm runtime')
    parser.add_argument(
        '--LD_LIBRARY_PATH', dest='ld_library_path', default=None, help='LD_LIBRARY_PATH')
    parser.add_argument(
        '--tsc-path', dest='tsc_path', default=None, type=lambda arg: is_directory(parser, arg),
        help='the path of tsc')
    parser.add_argument('--hotfix', dest='hotfix', action='store_true', default=False,
        help='run hotfix tests')
    parser.add_argument('--hotreload', dest='hotreload', action='store_true', default=False,
        help='run hotreload tests')
    parser.add_argument('--coldfix', dest='coldfix', action='store_true', default=False,
        help='run coldfix tests')
    parser.add_argument('--coldreload', dest='coldreload', action='store_true', default=False,
        help='run coldreload tests')
    parser.add_argument('--base64', dest='base64', action='store_true', default=False,
        help='run base64 tests')
    parser.add_argument('--bytecode', dest='bytecode', action='store_true', default=False,
        help='run bytecode tests')
    parser.add_argument('--debugger', dest='debugger', action='store_true', default=False,
        help='run debugger tests')
    parser.add_argument('--debug', dest='debug', action='store_true', default=False,
        help='run debug tests')
    parser.add_argument('--enable-arkguard', action='store_true', dest='enable_arkguard', default=False,
        help='enable arkguard for compiler tests')
    parser.add_argument('--aop-transform', dest='aop_transform', action='store_true', default=False,
        help='run debug tests')

    return parser.parse_args()


class Test:
    def __init__(self, test_path, flags):
        self.path = test_path
        self.flags = flags
        self.output = None
        self.error = None
        self.passed = None
        self.skipped = None
        self.reproduce = ""

    def log_cmd(self, cmd):
        self.reproduce += "\n" + ' '.join(cmd)

    def get_path_to_expected(self):
        if self.path.find(".d.ts") == -1:
            return "%s-expected.txt" % (path.splitext(self.path)[0])
        return "%s-expected.txt" % (self.path[:self.path.find(".d.ts")])

    def run(self, runner):
        test_abc_name = ("%s.abc" % (path.splitext(self.path)[0])).replace("/", "_")
        test_abc_path = path.join(runner.build_dir, test_abc_name)
        cmd = runner.cmd_prefix + [runner.es2panda]
        cmd.extend(self.flags)
        cmd.extend(["--output=" + test_abc_path])
        cmd.append(self.path)

        self.log_cmd(cmd)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")

        expected_path = self.get_path_to_expected()
        try:
            with open(expected_path, 'r') as fp:
                expected = fp.read()
            self.passed = expected == self.output and process.returncode in [
                0, 1]
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        if os.path.exists(test_abc_path):
            os.remove(test_abc_path)

        return self


class TSCTest(Test):
    def __init__(self, test_path, flags):
        Test.__init__(self, test_path, flags)
        self.options = self.parse_options()

    def parse_options(self):
        test_options = {}

        with open(self.path, "r", encoding="latin1") as f:
            lines = f.read()
            options = re.findall(r"//\s?@\w+:.*\n", lines)

            for option in options:
                separated = option.split(":")
                opt = re.findall(r"\w+", separated[0])[0].lower()
                value = separated[1].strip().lower()

                if opt == "filename":
                    if opt in options:
                        test_options[opt].append(value)
                    else:
                        test_options[opt] = [value]

                elif opt == "lib" or opt == "module":
                    test_options[opt] = [each.strip()
                                         for each in value.split(",")]
                elif value == "true" or value == "false":
                    test_options[opt] = value.lower() == "true"
                else:
                    test_options[opt] = value

            # TODO: Possibility of error: all exports will be catched, even the commented ones
            if 'module' not in test_options and re.search(r"export ", lines):
                test_options['module'] = []

        return test_options

    def run(self, runner):
        cmd = runner.cmd_prefix + [runner.es2panda, '--parse-only']
        cmd.extend(self.flags)
        if "module" in self.options:
            cmd.append('--module')
        cmd.append(self.path)

        self.log_cmd(cmd)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore")

        self.passed = True if process.returncode == 0 else False

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        return self

class TestAop:
    def __init__(self, cmd, compare_str, compare_abc_str, remove_file):
        self.cmd = cmd
        self.compare_str = compare_str
        self.compare_abc_str = compare_abc_str
        self.remove_file = remove_file
        self.path = ''
        self.output = None
        self.error = None
        self.passed = None
        self.skipped = None
        self.reproduce = ""

    def log_cmd(self, cmd):
        self.reproduce += ''.join(["\n", ' '.join(cmd)])

    def run(self, runner):
        cmd = self.cmd
        self.log_cmd(cmd)

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")

        if self.compare_str == '':
            self.passed = True
        else :
            self.passed = self.output.startswith(self.compare_str) and process.returncode in [0, 1]
            if self.remove_file != '' and os.path.exists(self.remove_file):
                os.remove(self.remove_file)

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        abc_path = path.join(os.getcwd(), 'test_aop.abc')
        if os.path.exists(abc_path):
            if self.compare_abc_str != '':
                with open(abc_path, "r") as abc_file:
                    self.passed = self.passed and abc_file.read() == self.compare_abc_str
            os.remove(abc_path)

        return self

class Runner:
    def __init__(self, args, name):
        self.test_root = path.dirname(path.abspath(__file__))
        self.args = args
        self.name = name
        self.tests = []
        self.failed = 0
        self.passed = 0
        self.es2panda = path.join(args.build_dir, 'es2abc')
        self.build_dir = args.build_dir
        self.cmd_prefix = []
        self.ark_js_vm = ""
        self.ark_aot_compiler = ""
        self.ld_library_path = ""

        if args.js_runtime_path:
            self.ark_js_vm = path.join(args.js_runtime_path, 'ark_js_vm')
            self.ark_aot_compiler = path.join(args.js_runtime_path, 'ark_aot_compiler')

        if args.ld_library_path:
            self.ld_library_path = args.ld_library_path

        if args.arm64_qemu:
            self.cmd_prefix = ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/"]

        if args.arm32_qemu:
            self.cmd_prefix = ["qemu-arm", "-L", "/usr/arm-linux-gnueabi"]

        if not path.isfile(self.es2panda):
            raise Exception("Cannot find es2panda binary: %s" % self.es2panda)

    def add_directory(self, directory, extension, flags):
        pass

    def test_path(self, src):
        pass

    def run_test(self, test):
        return test.run(self)

    def run(self):
        pool = multiprocessing.Pool()
        result_iter = pool.imap_unordered(
            self.run_test, self.tests, chunksize=32)
        pool.close()

        if self.args.progress:
            from tqdm import tqdm
            result_iter = tqdm(result_iter, total=len(self.tests))

        results = []
        for res in result_iter:
            results.append(res)

        self.tests = results
        pool.join()

    def deal_error(self, test):
        path_str = test.path
        err_col = {}
        if test.error:
            err_str = test.error.split('[')[0] if "patchfix" not in test.path else " patchfix throw error failed"
            err_col = {"path" : [path_str], "status": ["fail"], "error" : [test.error], "type" : [err_str]}
        else:
            err_col = {"path" : [path_str], "status": ["fail"], "error" : ["Segmentation fault"],
                        "type" : ["Segmentation fault"]}
        return err_col

    def summarize(self):
        print("")
        fail_list = []
        success_list = []

        for test in self.tests:
            assert(test.passed is not None)
            if not test.passed:
                fail_list.append(test)
            else:
                success_list.append(test)

        if len(fail_list):
            if self.args.error:
                import pandas as pd
                test_list = pd.DataFrame(columns=["path", "status", "error", "type"])
            for test in success_list:
                suc_col = {"path" : [test.path], "status": ["success"], "error" : ["success"], "type" : ["success"]}
                if self.args.error:
                    test_list = pd.concat([test_list, pd.DataFrame(suc_col)])
            print("Failed tests:")
            for test in fail_list:
                print(self.test_path(test.path))

                if self.args.error:
                    print("steps:", test.reproduce)
                    print("error:")
                    print(test.error)
                    print("\n")
                    err_col = self.deal_error(test)
                    test_list = pd.concat([test_list, pd.DataFrame(err_col)])

            if self.args.error:
                test_list.to_csv('test_statistics.csv', index=False)
                test_list["type"].value_counts().to_csv('type_statistics.csv', index_label="error")
                print("Type statistics:\n", test_list["type"].value_counts())
            print("")

        print("Summary(%s):" % self.name)
        print("\033[37mTotal:   %5d" % (len(self.tests)))
        print("\033[92mPassed:  %5d" % (len(self.tests) - len(fail_list)))
        print("\033[91mFailed:  %5d" % (len(fail_list)))
        print("\033[0m")

        return len(fail_list)


class RegressionRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Regression")

    def add_directory(self, directory, extension, flags, func=Test):
        glob_expression = path.join(
            self.test_root, directory, "*.%s" % (extension))
        files = glob(glob_expression)
        files = fnmatch.filter(files, self.test_root + '**' + self.args.filter)

        self.tests += list(map(lambda f: func(f, flags), files))

    def test_path(self, src):
        return src

class AbcToAsmRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Abc2asm")

    def add_directory(self, directory, extension, flags, func=Test):
        glob_expression = path.join(
            self.test_root, directory, "*.%s" % (extension))
        files = glob(glob_expression)
        files = fnmatch.filter(files, self.test_root + '**' + self.args.filter)

        self.tests += list(map(lambda f: AbcToAsmTest(f, flags), files))

    def test_path(self, src):
        return os.path.basename(src)

class AbcToAsmTest(Test):
    def run(self, runner):
        output_abc_file = ("%s.abc" % (path.splitext(self.path)[0])).replace("/", "_")
        gen_abc_cmd = runner.cmd_prefix + [runner.es2panda]
        gen_abc_cmd.extend(["--dump-asm-program", "--debug-info", "--output=" + output_abc_file])
        gen_abc_cmd.append(self.path)
        self.log_cmd(gen_abc_cmd)
        process_gen_abc = subprocess.Popen(gen_abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        gen_abc_out, gen_abc_err = process_gen_abc.communicate()
        gen_abc_output = gen_abc_out.decode("utf-8", errors="ignore") + gen_abc_err.decode("utf-8", errors="ignore")
        # If no abc file is generated, an error occurs during parser, but abc2asm function is normal.
        if not os.path.exists(output_abc_file):
            self.passed = True
            return self
        abc_to_asm_cmd = runner.cmd_prefix + [runner.es2panda]
        abc_to_asm_cmd.extend(["--dump-asm-program", "--debug-info", "--enable-abc-input"])
        abc_to_asm_cmd.append(output_abc_file)
        self.log_cmd(abc_to_asm_cmd)
        process_abc_to_asm = subprocess.Popen(abc_to_asm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        abc_to_asm_out, abc_to_asm_err = process_abc_to_asm.communicate()
        abc_to_asm_output = (abc_to_asm_out.decode("utf-8", errors="ignore") +
                             abc_to_asm_err.decode("utf-8", errors="ignore"))
        try:
            self.passed = gen_abc_output == abc_to_asm_output and process_abc_to_asm.returncode in [0, 1]
        except Exception:
            self.passed = False

        if not self.passed:
            print("**********Error testcase**********")
            print(self.path)
            print("**********Gen abc cmd**********")
            print(gen_abc_cmd)
            print(gen_abc_output)
            print("**********Abc to asm cmd***********")
            print(abc_to_asm_cmd)
            print(abc_to_asm_output)
        os.remove(output_abc_file)
        return self


class TSCRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "TSC")

        if self.args.tsc_path:
            self.tsc_path = self.args.tsc_path
        else :
            self.tsc_path = prepare_tsc_testcases(self.test_root)

        self.add_directory("conformance", [])
        self.add_directory("compiler", [])

    def add_directory(self, directory, flags):
        ts_suite_dir = path.join(self.tsc_path, 'tests/cases')

        glob_expression = path.join(
            ts_suite_dir, directory, "**/*.ts")
        files = glob(glob_expression, recursive=True)
        files = fnmatch.filter(files, ts_suite_dir + '**' + self.args.filter)

        for f in files:
            test_name = path.basename(f.split(".ts")[0])
            negative_references = path.join(
                self.tsc_path, 'tests/baselines/reference')
            is_negative = path.isfile(path.join(negative_references,
                                                test_name + ".errors.txt"))
            test = TSCTest(f, flags)

            if 'target' in test.options:
                targets = test.options['target'].replace(" ", "").split(',')
                for target in targets:
                    if path.isfile(path.join(negative_references,
                                             test_name + "(target=%s).errors.txt" % (target))):
                        is_negative = True
                        break

            if is_negative or "filename" in test.options:
                continue

            with open(path.join(self.test_root, 'test_tsc_ignore_list.txt'), 'r') as failed_references:
                if self.args.skip:
                    if path.relpath(f, self.tsc_path) in failed_references.read():
                        continue

            self.tests.append(test)

    def test_path(self, src):
        return src


class CompilerRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Compiler")

    def add_directory(self, directory, extension, flags):
        if directory.endswith("projects"):
            projects_path = path.join(self.test_root, directory)
            for project in os.listdir(projects_path):
                glob_expression = path.join(projects_path, project, "**/*.%s" % (extension))
                files = glob(glob_expression, recursive=True)
                files = fnmatch.filter(files, self.test_root + '**' + self.args.filter)
                self.tests.append(CompilerProjectTest(projects_path, project, files, flags))
        else:
            glob_expression = path.join(
                self.test_root, directory, "**/*.%s" % (extension))
            files = glob(glob_expression, recursive=True)
            files = fnmatch.filter(files, self.test_root + '**' + self.args.filter)
            self.tests += list(map(lambda f: CompilerTest(f, flags), files))

    def test_path(self, src):
        return src


class CompilerTest(Test):
    def __init__(self, test_path, flags):
        Test.__init__(self, test_path, flags)

    def execute_arkguard(self, runner):
        input_file_path = self.path
        arkguard_root_dir = os.path.join(runner.test_root, "../../arkguard")
        arkgurad_entry_path = os.path.join(arkguard_root_dir, "lib/cli/SecHarmony.js")
        config_path = os.path.join(arkguard_root_dir, "test/compilerTestConfig.json")
        arkguard_cmd = [
            'node',
            '--no-warnings',
            arkgurad_entry_path,
            input_file_path,
            '--config-path',
            config_path,
            '--inplace'
        ]
        self.log_cmd(arkguard_cmd)
        process = subprocess.Popen(arkguard_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        process.wait()
        success = True
        if err or process.returncode != 0:
            success = False
            self.passed = False
            self.error = err.decode("utf-8", errors="ignore")
        return success

    def run(self, runner):
        test_abc_name = ("%s.abc" % (path.splitext(self.path)[0])).replace("/", "_")
        test_abc_path = path.join(runner.build_dir, test_abc_name)
        es2abc_cmd = runner.cmd_prefix + [runner.es2panda]
        es2abc_cmd.extend(self.flags)
        es2abc_cmd.extend(["--output=" + test_abc_path])
        es2abc_cmd.append(self.path)
        self.log_cmd(es2abc_cmd)

        enable_arkguard = runner.args.enable_arkguard
        if enable_arkguard:
            success = self.execute_arkguard(runner)
            if not success:
                return self

        process = subprocess.Popen(es2abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if "--dump-assembly" in self.flags:
            pa_expected_path = "".join([self.get_path_to_expected()[:self.get_path_to_expected().rfind(".txt")],
                                       ".pa.txt"])
            self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
            try:
                with open(pa_expected_path, 'r') as fp:
                    expected = fp.read()
                self.passed = expected == self.output and process.returncode in [0, 1]
            except Exception:
                self.passed = False
            if not self.passed:
                self.error = err.decode("utf-8", errors="ignore")
                if os.path.exists(test_abc_path):
                    os.remove(test_abc_path)
                return self
        if err:
            self.passed = False
            self.error = err.decode("utf-8", errors="ignore")
            return self

        ld_library_path = runner.ld_library_path
        os.environ.setdefault("LD_LIBRARY_PATH", ld_library_path)
        run_abc_cmd = [runner.ark_js_vm]
        run_abc_cmd.extend([test_abc_path])
        self.log_cmd(run_abc_cmd)

        process = subprocess.Popen(run_abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
        expected_path = self.get_path_to_expected()
        try:
            with open(expected_path, 'r') as fp:
                expected = fp.read()
            self.passed = expected == self.output and process.returncode in [0, 1]
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        os.remove(test_abc_path)

        return self


class CompilerProjectTest(Test):
    def __init__(self, projects_path, project, test_paths, flags):
        Test.__init__(self, "", flags)
        self.projects_path = projects_path
        self.project = project
        self.test_paths = test_paths
        self.files_info_path = os.path.join(os.path.join(self.projects_path, self.project), 'filesInfo.txt')
        # Skip execution if --dump-assembly exists in flags
        self.requires_execution = "--dump-assembly" not in self.flags
        self.file_record_mapping = None

    def remove_project(self, runner):
        project_path = runner.build_dir + "/" + self.project
        if path.exists(project_path):
            shutil.rmtree(project_path)
        if path.exists(self.files_info_path):
            os.remove(self.files_info_path)

    def get_file_absolute_path_and_name(self, runner):
        sub_path = self.path[len(self.projects_path):]
        file_relative_path = path.split(sub_path)[0]
        file_name = path.split(sub_path)[1]
        file_absolute_path = runner.build_dir + "/" + file_relative_path
        return [file_absolute_path, file_name]

    def gen_single_abc(self, runner):
        for test_path in self.test_paths:
            self.path = test_path
            [file_absolute_path, file_name] = self.get_file_absolute_path_and_name(runner)
            if not path.exists(file_absolute_path):
                os.makedirs(file_absolute_path)

            test_abc_name = ("%s.abc" % (path.splitext(file_name)[0]))
            test_abc_path = path.join(file_absolute_path, test_abc_name)
            es2abc_cmd = runner.cmd_prefix + [runner.es2panda]
            es2abc_cmd.extend(self.flags)
            es2abc_cmd.extend(['%s%s' % ("--output=", test_abc_path)])
            es2abc_cmd.append(self.path)
            self.log_cmd(es2abc_cmd)

            process = subprocess.Popen(es2abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = process.communicate()
            if err:
                self.passed = False
                self.error = err.decode("utf-8", errors="ignore")
                self.remove_project(runner)
                return self

    def gen_record_name(self, test_path):
        record_name = os.path.relpath(test_path, os.path.dirname(self.files_info_path)).split('.')[0]
        if (self.file_record_mapping != None and record_name in self.file_record_mapping):
            record_name = self.file_record_mapping[record_name]
        return record_name

    def gen_files_info(self, runner):
        record_names_path = os.path.join(os.path.join(self.projects_path, self.project), 'recordnames.txt')
        if path.exists(record_names_path):
            with open(record_names_path) as mapping_fp:
                mapping_lines = mapping_fp.readlines()
                self.file_record_mapping = {}
                for mapping_line in mapping_lines:
                    cur_mapping = mapping_line[:-1].split(":")
                    self.file_record_mapping[cur_mapping[0]] = cur_mapping[1]
        fd = os.open(self.files_info_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        f = os.fdopen(fd, "w")
        for test_path in self.test_paths:
            record_name = self.gen_record_name(test_path)
            module_kind = "esm"
            file_info = ('%s;%s;%s;%s;%s' % (test_path, record_name, module_kind, test_path, record_name))
            f.writelines(file_info + '\n')
        f.close()

    def gen_merged_abc(self, runner):
        for test_path in self.test_paths:
            self.path = test_path
            if (self.path.endswith("-exec.ts")):
                exec_file_path = self.path
                [file_absolute_path, file_name] = self.get_file_absolute_path_and_name(runner)
                if not path.exists(file_absolute_path):
                    os.makedirs(file_absolute_path)
                test_abc_name = ("%s.abc" % (path.splitext(file_name)[0]))
                output_abc_name = path.join(file_absolute_path, test_abc_name)
        es2abc_cmd = runner.cmd_prefix + [runner.es2panda]
        es2abc_cmd.extend(self.flags)
        es2abc_cmd.extend(['%s%s' % ("--output=", output_abc_name)])
        es2abc_cmd.append('@' + os.path.join(os.path.dirname(exec_file_path), "filesInfo.txt"))
        self.log_cmd(es2abc_cmd)
        self.path = exec_file_path
        process = subprocess.Popen(es2abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()

        if "--dump-assembly" in self.flags:
            pa_expected_path = "".join([self.get_path_to_expected()[:self.get_path_to_expected().rfind(".txt")],
                                        ".pa.txt"])
            self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
            try:
                with open(pa_expected_path, 'r') as fp:
                    expected = fp.read()
                self.passed = expected == self.output and process.returncode in [0, 1]
            except Exception:
                self.passed = False
            if not self.passed:
                self.error = err.decode("utf-8", errors="ignore")
                self.remove_project(runner)
                return self

        if err:
            self.passed = False
            self.error = err.decode("utf-8", errors="ignore")
            self.remove_project(runner)
            return self

    def run(self, runner):
        # Compile all ts source files in the project to abc files.
        if ("--merge-abc" in self.flags):
            self.gen_files_info(runner)
            self.gen_merged_abc(runner)
        else:
            self.gen_single_abc(runner)

        if (not self.requires_execution):
            self.remove_project(runner)
            return self

        # Run test files that need to be executed in the project.
        for test_path in self.test_paths:
            self.path = test_path
            if self.path.endswith("-exec.ts"):
                [file_absolute_path, file_name] = self.get_file_absolute_path_and_name(runner)

                entry_point_name = path.splitext(file_name)[0]
                test_abc_name = ("%s.abc" % entry_point_name)
                test_abc_path = path.join(file_absolute_path, test_abc_name)

                ld_library_path = runner.ld_library_path
                os.environ.setdefault("LD_LIBRARY_PATH", ld_library_path)
                run_abc_cmd = [runner.ark_js_vm]
                if ("--merge-abc" in self.flags):
                    run_abc_cmd.extend(["--entry-point", entry_point_name])
                run_abc_cmd.extend([test_abc_path])
                self.log_cmd(run_abc_cmd)

                process = subprocess.Popen(run_abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = process.communicate()
                self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
                expected_path = self.get_path_to_expected()
                try:
                    with open(expected_path, 'r') as fp:
                        expected = fp.read()
                    self.passed = expected == self.output and process.returncode in [0, 1]
                except Exception:
                    self.passed = False

                if not self.passed:
                    self.error = err.decode("utf-8", errors="ignore")
                    self.remove_project(runner)
                    return self

            self.passed = True

        self.remove_project(runner)
        return self


class TSDeclarationTest(Test):
    def get_path_to_expected(self):
        file_name = self.path[:self.path.find(".d.ts")]
        return "%s-expected.txt" % file_name


class BcVersionRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Target bc version")
        self.ts2abc = path.join(self.test_root, '..', 'scripts', 'ts2abc.js')

    def add_cmd(self):
        for api_version in range(8, 14):
            cmd = self.cmd_prefix + [self.es2panda]
            cmd += ["--target-bc-version"]
            cmd += ["--target-api-version"]
            cmd += [str(api_version)]
            self.tests += [BcVersionTest(cmd, api_version)]
            node_cmd = ["node"] + [self.ts2abc]
            node_cmd += ["".join(["es2abc=", self.es2panda])]
            node_cmd += ["--target-api-version"]
            node_cmd += [str(api_version)]
            self.tests += [BcVersionTest(node_cmd, api_version)]

    def run(self):
        for test in self.tests:
            test.run()


class BcVersionTest(Test):
    def __init__(self, cmd, api_version):
        Test.__init__(self, "", 0)
        self.cmd = cmd
        self.api_version = api_version
        self.bc_version_expect = {
            8: "12.0.2.0",
            9: "9.0.0.0",
            10: "9.0.0.0",
            11: "11.0.2.0",
            12: "12.0.2.0",
            13: "12.0.2.0"
        }
        self.es2abc_script_expect = {
            8: "0.0.0.2",
            9: "9.0.0.0",
            10: "9.0.0.0",
            11: "11.0.2.0",
            12: "12.0.2.0",
            13: "12.0.2.0"
        }
    
    def run(self):
        process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
        if self.cmd[0] == "node":
            self.passed = self.es2abc_script_expect.get(self.api_version) == self.output and process.returncode in [0, 1]
        else:
            self.passed = self.bc_version_expect.get(self.api_version) == self.output and process.returncode in [0, 1]
        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")
        return self


class TransformerRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Transformer")

    def add_directory(self, directory, extension, flags):
        glob_expression = path.join(
            self.test_root, directory, "**/*.%s" % (extension))
        files = glob(glob_expression, recursive=True)
        files = fnmatch.filter(files, self.test_root + '**' + self.args.filter)

        self.tests += list(map(lambda f: TransformerTest(f, flags), files))

    def test_path(self, src):
        return src


class TransformerTest(Test):
    def __init__(self, test_path, flags):
        Test.__init__(self, test_path, flags)

    def get_path_to_expected(self):
        return "%s-transformed-expected.txt" % (path.splitext(self.path)[0])

    def run(self, runner):
        cmd = runner.cmd_prefix + [runner.es2panda]
        cmd.extend(self.flags)
        cmd.append(self.path)

        self.log_cmd(cmd)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")

        expected_path = self.get_path_to_expected()
        try:
            with open(expected_path, 'r') as fp:
                expected = fp.read()
            self.passed = expected == self.output and process.returncode in [0, 1]
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        return self


class PatchTest(Test):
    def __init__(self, test_path, mode_arg):
        Test.__init__(self, test_path, "")
        self.mode = mode_arg

    def gen_cmd(self, runner):
        symbol_table_file = 'base.map'
        origin_input_file = 'base.js'
        origin_output_abc = 'base.abc'
        modified_input_file = 'base_mod.js'
        modified_output_abc = 'patch.abc'

        gen_base_cmd = runner.cmd_prefix + [runner.es2panda, '--module']
        if 'record-name-with-dots' in os.path.basename(self.path):
            gen_base_cmd.extend(['--merge-abc', '--record-name=record.name.with.dots'])
        gen_base_cmd.extend(['--dump-symbol-table', os.path.join(self.path, symbol_table_file)])
        gen_base_cmd.extend(['--output', os.path.join(self.path, origin_output_abc)])
        gen_base_cmd.extend([os.path.join(self.path, origin_input_file)])
        self.log_cmd(gen_base_cmd)

        if self.mode == 'hotfix':
            mode_arg = ["--generate-patch"]
        elif self.mode == 'hotreload':
            mode_arg = ["--hot-reload"]
        elif self.mode == 'coldfix':
            mode_arg = ["--generate-patch", "--cold-fix"]
        elif self.mode == 'coldreload':
            mode_arg = ["--cold-reload"]

        patch_test_cmd = runner.cmd_prefix + [runner.es2panda, '--module']
        patch_test_cmd.extend(mode_arg)
        patch_test_cmd.extend(['--input-symbol-table', os.path.join(self.path, symbol_table_file)])
        patch_test_cmd.extend(['--output', os.path.join(self.path, modified_output_abc)])
        patch_test_cmd.extend([os.path.join(self.path, modified_input_file)])
        if 'record-name-with-dots' in os.path.basename(self.path):
            patch_test_cmd.extend(['--merge-abc', '--record-name=record.name.with.dots'])
        dump_assembly_testname = [
            'modify-anon-content-keep-origin-name',
            'modify-class-memeber-function',
            'exist-lexenv-3',
            'lexenv-reduce',
            'lexenv-increase']
        for name in dump_assembly_testname:
            if name in os.path.basename(self.path):
                patch_test_cmd.extend(['--dump-assembly'])
        self.log_cmd(patch_test_cmd)

        return gen_base_cmd, patch_test_cmd

    def run(self, runner):
        gen_base_cmd, patch_test_cmd = self.gen_cmd(runner)

        process_base = subprocess.Popen(gen_base_cmd, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout_base, stderr_base = process_base.communicate(timeout=runner.args.es2panda_timeout)
        if stderr_base:
            self.passed = False
            self.error = stderr_base.decode("utf-8", errors="ignore")
            self.output = stdout_base.decode("utf-8", errors="ignore") + stderr_base.decode("utf-8", errors="ignore")
        else:
            process_patch = subprocess.Popen(patch_test_cmd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            stdout_patch, stderr_patch = process_patch.communicate(timeout=runner.args.es2panda_timeout)
            if stderr_patch:
                self.passed = False
                self.error = stderr_patch.decode("utf-8", errors="ignore")
            self.output = stdout_patch.decode("utf-8", errors="ignore") + stderr_patch.decode("utf-8", errors="ignore")

        expected_path = os.path.join(self.path, 'expected.txt')
        try:
            with open(expected_path, 'r') as fp:
                # ignore license description lines and skip leading blank lines
                expected = (''.join((fp.readlines()[12:]))).lstrip()
            self.passed = expected == self.output
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = "expected output:" + os.linesep + expected + os.linesep + "actual output:" + os.linesep +\
                self.output

        return self


class PatchRunner(Runner):
    def __init__(self, args, name):
        Runner.__init__(self, args, name)
        self.preserve_files = args.error

    def __del__(self):
        if not self.preserve_files:
            self.clear_directory()

    def add_directory(self):
        self.tests_in_dirs = []
        for item in self.test_directory:
            glob_expression = path.join(item, "*")
            self.tests_in_dirs += glob(glob_expression, recursive=False)

    def clear_directory(self):
        for test in self.tests_in_dirs:
            files_in_dir = os.listdir(test)
            filtered_files = [file for file in files_in_dir if file.endswith(".map") or file.endswith(".abc")]
            for file in filtered_files:
                os.remove(os.path.join(test, file))

    def test_path(self, src):
        return os.path.basename(src)


class HotfixRunner(PatchRunner):
    def __init__(self, args):
        PatchRunner.__init__(self, args, "Hotfix")
        self.test_directory = [path.join(self.test_root, "hotfix", "hotfix-throwerror"),
            path.join(self.test_root, "hotfix", "hotfix-noerror")]
        self.add_directory()
        self.tests += list(map(lambda t: PatchTest(t, "hotfix"), self.tests_in_dirs))


class HotreloadRunner(PatchRunner):
    def __init__(self, args):
        PatchRunner.__init__(self, args, "Hotreload")
        self.test_directory = [path.join(self.test_root, "hotreload", "hotreload-throwerror"),
            path.join(self.test_root, "hotreload", "hotreload-noerror")]
        self.add_directory()
        self.tests += list(map(lambda t: PatchTest(t, "hotreload"), self.tests_in_dirs))


class ColdfixRunner(PatchRunner):
    def __init__(self, args):
        PatchRunner.__init__(self, args, "Coldfix")
        self.test_directory = [path.join(self.test_root, "coldfix", "coldfix-throwerror"),
            path.join(self.test_root, "coldfix", "coldfix-noerror")]
        self.add_directory()
        self.tests += list(map(lambda t: PatchTest(t, "coldfix"), self.tests_in_dirs))


class ColdreloadRunner(PatchRunner):
    def __init__(self, args):
        PatchRunner.__init__(self, args, "Coldreload")
        self.test_directory = [path.join(self.test_root, "coldreload")]
        self.add_directory()
        self.tests += list(map(lambda t: PatchTest(t, "coldreload"), self.tests_in_dirs))


class DebuggerTest(Test):
    def __init__(self, test_path, mode):
        Test.__init__(self, test_path, "")
        self.mode = mode

    def run(self, runner):
        cmd = runner.cmd_prefix + [runner.es2panda, "--module"]
        input_file_name = 'base.js'
        if self.mode == "debug-mode":
            cmd.extend(['--debug-info'])
        cmd.extend([os.path.join(self.path, input_file_name)])
        cmd.extend(['--dump-assembly'])


        self.log_cmd(cmd)

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=runner.args.es2panda_timeout)
        if stderr:
            self.passed = False
            self.error = stderr.decode("utf-8", errors="ignore")
            return self

        self.output = stdout.decode("utf-8", errors="ignore")

        expected_path = os.path.join(self.path, 'expected.txt')
        try:
            with open(expected_path, 'r') as fp:
                expected = (''.join((fp.readlines()[12:]))).lstrip()
            self.passed = expected == self.output
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = "expected output:" + os.linesep + expected + os.linesep + "actual output:" + os.linesep +\
                self.output

        return self


class DebuggerRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "debugger")
        self.test_directory = path.join(self.test_root, "debugger")
        self.add_test()

    def add_test(self):
        self.tests = []
        self.tests.append(DebuggerTest(os.path.join(self.test_directory, "debugger-in-debug"), "debug-mode"))
        self.tests.append(DebuggerTest(os.path.join(self.test_directory, "debugger-in-release"), "release-mode"))


class Base64Test(Test):
    def __init__(self, test_path, input_type):
        Test.__init__(self, test_path, "")
        self.input_type = input_type

    def run(self, runner):
        cmd = runner.cmd_prefix + [runner.es2panda, "--base64Output"]
        if self.input_type == "file":
            input_file_name = 'input.js'
            cmd.extend(['--source-file', input_file_name])
            cmd.extend([os.path.join(self.path, input_file_name)])
        elif self.input_type == "string":
            input_file = os.path.join(self.path, "input.txt")
            try:
                with open(input_file, 'r') as fp:
                    base64_input = (''.join((fp.readlines()[12:]))).lstrip()  # ignore license description lines
                    cmd.extend(["--base64Input", base64_input])
            except Exception:
                self.passed = False
        elif self.input_type == "targetApiVersion":
            # base64 test for all available target api version.
            version = os.path.basename(self.path)
            cmd.extend(['--target-api-version', version])
            input_file = os.path.join(self.path, "input.txt")
            try:
                with open(input_file, 'r') as fp:
                    base64_input = (''.join((fp.readlines()[12:]))).lstrip()  # ignore license description lines
                    cmd.extend(["--base64Input", base64_input])
            except Exception:
                self.passed = False
        else:
            self.error = "Unsupported base64 input type"
            self.passed = False
            return self

        self.log_cmd(cmd)

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=runner.args.es2panda_timeout)
        if stderr:
            self.passed = False
            self.error = stderr.decode("utf-8", errors="ignore")
            return self

        self.output = stdout.decode("utf-8", errors="ignore")

        expected_path = os.path.join(self.path, 'expected.txt')
        try:
            with open(expected_path, 'r') as fp:
                expected = (''.join((fp.readlines()[12:]))).lstrip()
            self.passed = expected == self.output
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = "expected output:" + os.linesep + expected + os.linesep + "actual output:" + os.linesep +\
                self.output

        return self


class Base64Runner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Base64")
        self.test_directory = path.join(self.test_root, "base64")
        self.add_test()

    def add_test(self):
        self.tests = []
        self.tests.append(Base64Test(os.path.join(self.test_directory, "inputFile"), "file"))
        self.tests.append(Base64Test(os.path.join(self.test_directory, "inputString"), "string"))
        # current target api version is 12, once a new version is addded, a new testcase should be added here.
        current_version = 12
        available_target_api_versions = [9, 10, 11, current_version]
        for version in available_target_api_versions:
            self.tests.append(Base64Test(os.path.join(self.test_directory, "availableTargetApiVersion", str(version)),
                "targetApiVersion"))

    def test_path(self, src):
        return os.path.basename(src)


class BytecodeRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Bytecode")

    def add_directory(self, directory, extension, flags, func=Test):
        glob_expression = path.join(
            self.test_root, directory, "**/*.%s" % (extension))
        files = glob(glob_expression, recursive=True)
        files = fnmatch.filter(files, self.test_root + '**' + self.args.filter)
        self.tests += list(map(lambda f: func(f, flags), files))

    def test_path(self, src):
        return src


class CompilerTestInfo(object):
    def __init__(self, directory, extension, flags):
        self.directory = directory
        self.extension = extension
        self.flags = flags

    def update_dir(self, prefiex_dir):
        self.directory = os.path.sep.join([prefiex_dir, self.directory])


# Copy compiler directory to test/.local directory, and do inplace obfuscation.
def prepare_for_obfuscation(compiler_test_infos, test_root):
    tmp_dir_name = ".local"
    tmp_path = os.path.join(test_root, tmp_dir_name)
    if not os.path.exists(tmp_path):
        os.mkdir(tmp_path)

    test_root_dirs = set()
    for info in compiler_test_infos:
        root_dir = info.directory.split("/")[0]
        test_root_dirs.add(root_dir)

    for test_dir in test_root_dirs:
        src_dir = os.path.join(test_root, test_dir)
        target_dir = os.path.join(tmp_path, test_dir)
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        shutil.copytree(src_dir, target_dir)

    for info in compiler_test_infos:
        info.update_dir(tmp_dir_name)

def add_directory_for_regression(runners, args):
    runner = RegressionRunner(args)
    runner.add_directory("parser/concurrent", "js", ["--module", "--dump-ast"])
    runner.add_directory("parser/js", "js", ["--parse-only", "--dump-ast"])
    runner.add_directory("parser/script", "ts", ["--parse-only", "--dump-ast"])
    runner.add_directory("parser/ts", "ts",
                         ["--parse-only", "--module", "--dump-ast"])
    runner.add_directory("parser/ts/type_checker", "ts",
                         ["--parse-only", "--enable-type-check", "--module", "--dump-ast"])
    runner.add_directory("parser/ts/cases/declaration", "d.ts",
                         ["--parse-only", "--module", "--dump-ast"], TSDeclarationTest)
    runner.add_directory("parser/commonjs", "js", ["--commonjs", "--parse-only", "--dump-ast"])
    runner.add_directory("parser/binder", "js", ["--dump-assembly"])
    runner.add_directory("parser/js/emptySource", "js", ["--dump-assembly"])
    runner.add_directory("parser/js/language/arguments-object", "js", ["--parse-only"])
    runner.add_directory("parser/js/language/statements/for-statement", "js", ["--parse-only", "--dump-ast"])
    runner.add_directory("parser/js/language/expressions/optional-chain", "js", ["--parse-only", "--dump-ast"])
    runner.add_directory("parser/sendable_class", "ts", ["--dump-assembly", "--dump-literal-buffer", "--module"])
    runner.add_directory("parser/unicode", "js", ["--parse-only"])
    runner.add_directory("parser/ts/stack_overflow", "ts", ["--parse-only", "--dump-ast"])

    runners.append(runner)

    transformer_runner = TransformerRunner(args)
    transformer_runner.add_directory("parser/ts/transformed_cases", "ts",
                                     ["--parse-only", "--module", "--dump-transformed-ast",
                                     "--check-transformed-ast-structure"])

    runners.append(transformer_runner)

    bc_version_runner = BcVersionRunner(args)
    bc_version_runner.add_cmd()

    runners.append(bc_version_runner)

def add_directory_for_asm(runners, args):
    runner = AbcToAsmRunner(args)
    runner.add_directory("abc2asm/js", "js", [])
    runner.add_directory("abc2asm/ts", "ts", [])
    runner.add_directory("compiler/js", "js", [])
    runner.add_directory("compiler/ts/cases/compiler", "ts", [])
    runner.add_directory("compiler/ts/projects", "ts", ["--module"])
    runner.add_directory("compiler/ts/projects", "ts", ["--module", "--merge-abc"])
    runner.add_directory("compiler/dts", "d.ts", ["--module", "--opt-level=0"])
    runner.add_directory("compiler/commonjs", "js", ["--commonjs"])
    runner.add_directory("compiler/recordsource/with-on", "js", ["--record-source"])
    runner.add_directory("compiler/recordsource/with-off", "js", [])
    runner.add_directory("parser/concurrent", "js", ["--module"])
    runner.add_directory("parser/js", "js", [])
    runner.add_directory("parser/script", "ts", [])
    runner.add_directory("parser/ts", "ts", ["--module"])
    runner.add_directory("parser/ts/type_checker", "ts", ["--enable-type-check", "--module"])
    runner.add_directory("parser/commonjs", "js", ["--commonjs"])
    runner.add_directory("parser/binder", "js", [])
    runner.add_directory("parser/js/emptySource", "js", [])
    runner.add_directory("parser/js/language/arguments-object", "js", [])
    runner.add_directory("parser/js/language/statements/for-statement", "js", [])
    runner.add_directory("parser/js/language/expressions/optional-chain", "js", [])
    runner.add_directory("parser/sendable_class", "ts", ["--module"])
    runner.add_directory("parser/unicode", "js", [])
    runner.add_directory("parser/ts/stack_overflow", "ts", [])

    runners.append(runner)

def add_directory_for_compiler(runners, args):
    runner = CompilerRunner(args)
    compiler_test_infos = []
    compiler_test_infos.append(CompilerTestInfo("compiler/js", "js", ["--module"]))
    compiler_test_infos.append(CompilerTestInfo("compiler/ts/cases", "ts", []))
    compiler_test_infos.append(CompilerTestInfo("compiler/ts/projects", "ts", ["--module"]))
    compiler_test_infos.append(CompilerTestInfo("compiler/ts/projects", "ts", ["--module", "--merge-abc"]))
    compiler_test_infos.append(CompilerTestInfo("compiler/dts", "d.ts", ["--module", "--opt-level=0"]))
    compiler_test_infos.append(CompilerTestInfo("compiler/commonjs", "js", ["--commonjs"]))
    compiler_test_infos.append(CompilerTestInfo("compiler/recordsource/with-on", "js", ["--record-source"]))
    compiler_test_infos.append(CompilerTestInfo("compiler/recordsource/with-off", "js", []))
    compiler_test_infos.append(CompilerTestInfo("compiler/interpreter/lexicalEnv", "js", []))
    compiler_test_infos.append(CompilerTestInfo("compiler/sendable", "ts", ["--module"]))
    compiler_test_infos.append(CompilerTestInfo("optimizer/js/branch-elimination", "js",
                                                ["--module", "--branch-elimination", "--dump-assembly"]))
    # This directory of test cases is for dump-assembly comparison only, and is not executed.
    # Check CompilerProjectTest for more details.
    compiler_test_infos.append(CompilerTestInfo("optimizer/ts/branch-elimination/projects", "ts",
                                                ["--module", "--branch-elimination", "--merge-abc", "--dump-assembly",
                                                "--file-threads=8"]))

    if args.enable_arkguard:
        prepare_for_obfuscation(compiler_test_infos, runner.test_root)

    for info in compiler_test_infos:
        runner.add_directory(info.directory, info.extension, info.flags)

    runners.append(runner)


def add_directory_for_bytecode(runners, args):
    runner = BytecodeRunner(args)
    runner.add_directory("bytecode/commonjs", "js", ["--commonjs", "--dump-assembly"])
    runner.add_directory("bytecode/js", "js", ["--dump-assembly"])
    runner.add_directory("bytecode/ts/cases", "ts", ["--dump-assembly"])
    runner.add_directory("bytecode/ts/api11", "ts", ["--dump-assembly", "--module", "--target-api-version=11"])
    runner.add_directory("bytecode/ts/api12", "ts", ["--dump-assembly", "--module", "--target-api-version=12"])
    runner.add_directory("bytecode/watch-expression", "js", ["--debugger-evaluate-expression", "--dump-assembly"])

    runners.append(runner)


def add_directory_for_debug(runners, args):
    runner = RegressionRunner(args)
    runner.add_directory("debug/parser", "js", ["--parse-only", "--dump-ast"])

    runners.append(runner)


def add_cmd_for_aop_transform(runners, args):
    runner = AopTransform(args)

    aop_file_path = path.join(runner.test_root + "/aop/")
    lib_suffix = '.so'
    #cpp src, deal type, result compare str, abc compare str
    msg_list = [
        ["correct_modify.cpp", "compile", "aop_transform_start", "new_abc_content"],
        ["correct_no_modify.cpp", "compile", "aop_transform_start", ""],
        ["exec_error.cpp", "compile", "Transform exec fail", ""],
        ["no_func_transform.cpp", "compile", "os::library_loader::ResolveSymbol get func Transform error", ""],
        ["error_format.cpp", "copy_lib", "os::library_loader::Load error", ""],
        ["".join(["no_exist", lib_suffix]), "dirct_use", "Failed to find file", ""],
        ["error_suffix.xxx", "direct_use", "aop transform file suffix support", ""]
    ]
    for i in range(0, len(msg_list)):
        cpp_file = ''.join([aop_file_path, msg_list[i][0]])
        if msg_list[i][1] == 'compile':
            lib_file = cpp_file.replace('.cpp', lib_suffix)
            remove_file = lib_file
            runner.add_cmd(["g++", "--share", "-o", lib_file, cpp_file], "", "", "")
        elif msg_list[i][1] == 'copy_lib':
            lib_file = cpp_file.replace('.cpp', lib_suffix)
            remove_file = lib_file
            if not os.path.exists(lib_file):
                with open(cpp_file, "rb") as source_file:
                    with open(lib_file, "wb") as target_file:
                        target_file.write(source_file.read())
        elif msg_list[i][1] == 'direct_use':
            lib_file = cpp_file
            remove_file = ""

        js_file = path.join(aop_file_path, "test_aop.js")
        runner.add_cmd([runner.es2panda, "--merge-abc", "--transform-lib", lib_file, js_file], msg_list[i][2], msg_list[i][3], remove_file)

    runners.append(runner)


class AopTransform(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "AopTransform")
    
    def add_cmd(self, cmd, compare_str, compare_abc_str, remove_file, func=TestAop):
        self.tests += [func(cmd, compare_str, compare_abc_str, remove_file)]

    def test_path(self, src):
        return src


def main():
    args = get_args()

    runners = []

    if args.regression:
        add_directory_for_regression(runners, args)

    if args.abc_to_asm:
        add_directory_for_asm(runners, args)

    if args.tsc:
        runners.append(TSCRunner(args))

    if args.compiler:
        add_directory_for_compiler(runners, args)

    if args.hotfix:
        runners.append(HotfixRunner(args))

    if args.hotreload:
        runners.append(HotreloadRunner(args))

    if args.coldfix:
        runners.append(ColdfixRunner(args))

    if args.coldreload:
        runners.append(ColdreloadRunner(args))

    if args.debugger:
        runners.append(DebuggerRunner(args))

    if args.base64:
        runners.append(Base64Runner(args))

    if args.bytecode:
        add_directory_for_bytecode(runners, args)

    if args.aop_transform:
        add_cmd_for_aop_transform(runners, args)

    if args.debug:
        add_directory_for_debug(runners, args)

    failed_tests = 0

    for runner in runners:
        runner.run()
        failed_tests += runner.summarize()

    # TODO: exit 1 when we have failed tests after all tests are fixed
    exit(0)


if __name__ == "__main__":
    main()
