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
import test262util


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
        '--test262', '-t', action='store_true', dest='test262', default=False,
        help='run test262 tests')
    parser.add_argument(
        '--error', action='store_true', dest='error', default=False,
        help='capture stderr')
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
        '--type-extractor', action='store_true', dest='type_extractor',
        default=False, help='run type extractor tests')
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
    parser.add_argument('--base64', dest='base64', action='store_true', default=False,
        help='run base64 tests')
    parser.add_argument('--bytecode', dest='bytecode', action='store_true', default=False,
        help='run bytecode tests')

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


class Test262Test(Test):
    def __init__(self, test_path, flags, test_id, with_optimizer):
        Test.__init__(self, test_path, flags)
        self.test_id = test_id
        self.fail_kind = None
        self.with_optimizer = with_optimizer

    class FailKind(Enum):
        ES2PANDA_FAIL = 1
        RUNTIME_FAIL = 2
        AOT_FAIL = 3
        ES2PANDA_TIMEOUT = 4
        RUNTIME_TIMEOUT = 5
        AOT_TIMEOUT = 6

    def run(self, runner):
        with open(self.path, 'r') as fp:
            header = runner.util.get_header(fp.read())
        desc = runner.util.parse_descriptor(header)

        test_abc = path.join(runner.tmp_dir, "%s.abc" % self.test_id)
        test_an = path.join(runner.tmp_dir, "%s.an" % self.test_id)

        directory = path.dirname(test_abc)
        os.makedirs(directory, exist_ok=True)

        cmd = runner.cmd_prefix + [runner.es2panda]
        if self.with_optimizer:
            cmd.append('--opt-level=2')
        cmd.extend(['--thread=0', '--output=%s' % (test_abc)])

        if 'module' in desc['flags']:
            cmd.append("--module")

        if 'noStrict' in desc['flags']:
            self.skipped = True
            return self

        cmd.append(self.path)

        self.log_cmd(cmd)

        if runner.args.verbose:
            print('Run es2panda: %s' % ' '.join(cmd), file=sys.stderr)

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=runner.cmd_env)

        try:
            output_res, err = process.communicate(runner.args.es2panda_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            self.passed = False
            self.fail_kind = self.FailKind.ES2PANDA_TIMEOUT
            self.error = self.fail_kind.name
            return self

        out = output_res.decode("utf-8", errors="ignore")
        err = err.decode("utf-8", errors="ignore")
        self.passed, need_exec = runner.util.validate_parse_result(
            process.returncode, err, desc, out)

        if not self.passed:
            self.fail_kind = self.FailKind.ES2PANDA_FAIL
            self.error = "out:{}\nerr:{}\ncode:{}".format(
                out, err, process.returncode)
            print(self.error)
            return self

        if not need_exec:
            self.passed = True
            return self

        if runner.args.aot:
            cmd = runner.cmd_prefix + [runner.arkaot]
            cmd.extend(runner.aot_args)
            cmd.extend(['--paoc-panda-files', test_abc])
            cmd.extend(['--paoc-output', test_an])

            if os.path.isfile(test_an):
                os.remove(test_an)

            self.log_cmd(cmd)

            if runner.args.verbose:
                print('Run ark_aot: %s' % ' '.join(cmd), file=sys.stderr)

            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=runner.cmd_env)

            try:
                out, err = process.communicate(runner.args.paoc_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                self.passed = False
                self.fail_kind = self.FailKind.AOT_TIMEOUT
                self.error = self.fail_kind.name
                return self

            if process.returncode != 0:
                self.passed = False
                self.fail_kind = self.FailKind.AOT_FAIL
                self.error = err.decode("utf-8", errors="ignore")
                return self

        cmd = runner.cmd_prefix + [runner.runtime]

        if runner.args.verbose:
            print('Run aot for arm64: %s' % ' '.join(cmd), file=sys.stderr)

        cmd.extend(runner.runtime_args)

        if runner.args.aot:
            cmd.extend(['--aot-files', test_an])

        if runner.args.jit:
            cmd.extend(['--compiler-enable-jit=true', '--compiler-hotness-threshold=0'])
        else:
            cmd.extend(['--compiler-enable-jit=false'])

        cmd.extend([test_abc, "_GLOBAL::func_main_0"])

        self.log_cmd(cmd)

        if runner.args.verbose:
            print('Run ark: %s' % ' '.join(cmd), file=sys.stderr)

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=runner.cmd_env)

        try:
            out, err = process.communicate(timeout=runner.args.timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            self.passed = False
            self.fail_kind = self.FailKind.RUNTIME_TIMEOUT
            self.error = self.fail_kind.name
            return self

        out = out.decode("utf-8", errors="ignore")
        err = err.decode("utf-8", errors="ignore")
        self.passed = runner.util.validate_runtime_result(
            process.returncode, err, desc, out)

        if not self.passed:
            self.fail_kind = self.FailKind.RUNTIME_FAIL
            self.error = "out:{}\nerr:{}\ncode:{}".format(
                out, err, process.returncode)
            print(self.error)

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


class Test262Runner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "Test262 ark"),

        self.cmd_env = os.environ.copy()
        for san in ["ASAN_OPTIONS", "TSAN_OPTIONS", "MSAN_OPTIONS", "LSAN_OPTIONS"]:
            # we don't want to interpret asan failures as SyntaxErrors
            self.cmd_env[san] = ":exitcode=255"

        self.update = args.update
        self.enable_skiplists = False if self.update else args.skip
        self.normal_skiplist_file = "test262skiplist.txt"
        self.long_flaky_skiplist_files = ["test262skiplist-long.txt", "test262skiplist-flaky.txt"]
        self.normal_skiplist = set([])
        self.runtime = path.join(args.build_dir, 'bin', 'ark')
        if not path.isfile(self.runtime):
            raise Exception("Cannot find runtime binary: %s" % self.runtime)

        self.runtime_args = [
            '--boot-panda-files=%s/pandastdlib/arkstdlib.abc'
            % args.build_dir,
            '--load-runtimes=ecmascript',
            '--gc-type=%s' % args.gc_type,
        ]

        if not args.no_gip:
            self.runtime_args += ['--run-gc-in-place']

        if args.aot:
            self.arkaot = path.join(args.build_dir, 'bin', 'ark_aot')
            if not path.isfile(self.arkaot):
                raise Exception("Cannot find aot binary: %s" % self.arkaot)

            self.aot_args = [
                '--boot-panda-files=%s/pandastdlib/arkstdlib.abc'
                % args.build_dir,
                '--load-runtimes=ecmascript',
                '--gc-type=%s' % args.gc_type,
            ]

            if not args.no_gip:
                self.aot_args += ['--run-gc-in-place']

            self.aot_args += args.aot_args
        else:
            self.aot_args = []

        self.skiplist_name_list = self.long_flaky_skiplist_files if self.update else []
        self.skiplist_bco_name = ""

        if self.enable_skiplists:
            self.skiplist_name_list.append(self.normal_skiplist_file)
            self.skiplist_name_list.extend(self.long_flaky_skiplist_files)

            if args.bco:
                self.skiplist_bco_name = "test262skiplist-bco.txt"
            if args.arm64_compiler_skip:
                self.skiplist_name_list.append("test262skiplist-compiler-arm64.txt")

        self.tmp_dir = path.join(path.sep, 'tmp', 'panda', 'test262')
        os.makedirs(self.tmp_dir, exist_ok=True)

        self.util = test262util.Test262Util()
        self.test262_dir = self.util.generate(
            '281eb10b2844929a7c0ac04527f5b42ce56509fd',
            args.build_dir,
            path.join(self.test_root, "test262harness.js"),
            args.progress)

        self.add_directory(self.test262_dir, "js", args.test_list, [])

    def add_directory(self, directory, extension, test_list_path, flags):
        glob_expression = path.join(directory, "**/*.%s" % (extension))
        files = glob(glob_expression, recursive=True)
        files = fnmatch.filter(files, path.join(directory, self.args.filter))

        def load_list(p):
            with open(p, 'r') as fp:
                return set(map(lambda e: path.join(directory, e.strip()), fp))

        skiplist = set([])

        for sl in self.skiplist_name_list:
            skiplist.update(load_list(path.join(self.test_root, sl)))

        if self.update:
            self.normal_skiplist.update(load_list(path.join(self.test_root, self.normal_skiplist_file)))

        skiplist_bco = set([])
        if self.skiplist_bco_name != "":
            skiplist_bco = load_list(path.join(self.test_root, self.skiplist_bco_name))

        if test_list_path is not None:
            test_list = load_list(path.abspath(test_list_path))
            files = filter(lambda f: f in test_list, files)

        def get_test_id(file):
            return path.relpath(path.splitext(file)[0], self.test262_dir)

        self.tests = list(map(lambda test: Test262Test(test, flags, get_test_id(test), test not in skiplist_bco),
                              filter(lambda f: f not in skiplist, files)))

    def test_path(self, src):
        return path.relpath(src, self.test262_dir)

    def run(self):
        Runner.run(self)
        self.update_skiplist()

    def summarize(self):
        print("")

        fail_lists = {}
        for kind in Test262Test.FailKind:
            fail_lists[kind] = []

        num_failed = 0
        num_skipped = 0
        for test in self.tests:
            if test.skipped:
                num_skipped += 1
                continue

            assert(test.passed is not None)
            if not test.passed:
                fail_lists[test.fail_kind].append(test)
                num_failed += 1

        def summarize_list(name, tests_list):
            if len(tests_list):
                tests_list.sort(key=lambda test: test.path)
                print("# " + name)
                for test in tests_list:
                    print(self.test_path(test.path))
                    if self.args.error:
                        print("steps:", test.reproduce)
                        print(test.error)
                print("")

        total_tests = len(self.tests) - num_skipped

        if not self.update:
            for kind in Test262Test.FailKind:
                summarize_list(kind.name, fail_lists[kind])

        print("Summary(%s):" % self.name)
        print("\033[37mTotal:   %5d" % (total_tests))
        print("\033[92mPassed:  %5d" % (total_tests - num_failed))
        print("\033[91mFailed:  %5d" % (num_failed))
        print("\033[0m")

        return num_failed

    def update_skiplist(self):
        if not self.update:
            return

        skiplist_es2panda = list({x.test_id + ".js" for x in self.tests
                                  if not x.skipped and not x.passed and
                                  x.fail_kind == Test262Test.FailKind.ES2PANDA_FAIL})
        skiplist_runtime = list({x.test_id + ".js" for x in self.tests
                                 if not x.skipped and not x.passed and
                                 x.fail_kind == Test262Test.FailKind.RUNTIME_FAIL})

        skiplist_es2panda.sort()
        skiplist_runtime.sort()

        new_skiplist = skiplist_es2panda + skiplist_runtime

        new_pass = list(filter(lambda x: len(x) and not x.startswith('#')
                               and x not in new_skiplist, self.normal_skiplist))
        new_fail = list(filter(lambda x: x not in self.normal_skiplist, new_skiplist))
        new_pass.sort()
        new_fail.sort()

        if new_pass:
            print("\033[92mRemoved from skiplist:")
            print("\n".join(new_pass))
            print("\033[0m")

        if new_fail:
            print("\033[91mNew tests on skiplist:")
            print("\n".join(new_fail))
            print("\033[0m")

        fd = os.open(path.join(self.test_root, self.normal_skiplist_file), os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        file = os.fdopen(fd, "w+")
        file.write("\n".join(["# ES2PANDA_FAIL"] + skiplist_es2panda + ["", "# RUNTIME_FAIL"] + skiplist_runtime))
        file.write("\n")
        file.close()


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

    def run(self, runner):
        test_abc_name = ("%s.abc" % (path.splitext(self.path)[0])).replace("/", "_")
        test_abc_path = path.join(runner.build_dir, test_abc_name)
        es2abc_cmd = runner.cmd_prefix + [runner.es2panda]
        es2abc_cmd.extend(self.flags)
        es2abc_cmd.extend(["--output=" + test_abc_path])
        es2abc_cmd.append(self.path)
        self.log_cmd(es2abc_cmd)

        process = subprocess.Popen(es2abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
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

    def gen_files_info(self, runner):
        fd = os.open(self.files_info_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        f = os.fdopen(fd, "w")
        for test_path in self.test_paths:
            record_name = os.path.relpath(test_path, os.path.dirname(self.files_info_path)).split('.')[0]
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
        process = subprocess.Popen(es2abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
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

    def run(self, runner):
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

        patch_test_cmd = runner.cmd_prefix + [runner.es2panda, '--module']
        patch_test_cmd.extend(mode_arg)
        patch_test_cmd.extend(['--input-symbol-table', os.path.join(self.path, symbol_table_file)])
        patch_test_cmd.extend(['--output', os.path.join(self.path, modified_output_abc)])
        patch_test_cmd.extend([os.path.join(self.path, modified_input_file)])
        if 'record-name-with-dots' in os.path.basename(self.path):
            patch_test_cmd.extend(['--merge-abc', '--record-name=record.name.with.dots'])
        if ('modify-anon-content-keep-origin-name' in os.path.basename(self.path) or
            'modify-class-memeber-function' in os.path.basename(self.path)):
            patch_test_cmd.extend(['--dump-assembly'])
        self.log_cmd(patch_test_cmd)
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

    def test_path(self, src):
        return os.path.basename(src)


class TypeExtractorRunner(Runner):
    def __init__(self, args):
        Runner.__init__(self, args, "TypeExtractor")

        if self.args.tsc_path:
            self.tsc_path = self.args.tsc_path
        else :
            self.tsc_path = prepare_tsc_testcases(self.test_root)

        self.add_tsc_directory("conformance", [])
        self.add_directory("testcases", [])
        self.add_directory("dts-testcases", [], True)
        self.add_directory("testcases_with_assert", [])
        self.add_directory("testcases_with_assert/projects", [], False, True)
        self.add_directory("testcases_with_running", [])

    def add_tsc_directory(self, directory, flags):
        ts_suite_dir = path.join(self.tsc_path, 'tests/cases')

        glob_expression = path.join(
            ts_suite_dir, directory, "**/*.ts")
        files = glob(glob_expression, recursive=True)
        files = fnmatch.filter(files, ts_suite_dir + '**' + self.args.filter)

        with open(path.join(self.test_root, 'type_extractor/testlist.txt'), 'r') as passed_references:
            for f in files:
                if path.relpath(f, self.tsc_path) in passed_references.read():
                    test = TypeExtractorTest(f, flags)
                    self.tests.append(test)

    def add_directory(self, directory, flags, is_dts_test=False, is_project=False):
        ts_suite_dir = path.join(self.test_root, 'type_extractor')

        if is_project:
            glob_expression = path.join(ts_suite_dir, directory, "**/*-main.ts")
        elif is_dts_test:
            glob_expression = path.join(ts_suite_dir, directory, "**/*.d.ts")
        else:
            glob_expression = path.join(ts_suite_dir, directory, "*.ts")
        files = glob(glob_expression, recursive=True)
        files = fnmatch.filter(files, ts_suite_dir + '**' + self.args.filter)
        for f in files:
            if directory.startswith("testcases_with_assert") or directory.startswith("testcases_with_running"):
                if (self.ld_library_path == "" or self.ark_aot_compiler == ""):
                    break
                test = TypeExtractorWithAOTTest(f, flags, directory.startswith("testcases_with_running"), directory.endswith("projects"))
                self.tests.append(test)
            else:
                test = TypeExtractorTest(f, flags, is_dts_test)
                self.tests.append(test)

    def test_path(self, src):
        return src


class TypeExtractorTest(Test):
    def __init__(self, test_path, flags, is_dts_test=False):
        Test.__init__(self, test_path, flags)
        self.is_dts_test = is_dts_test

    def run(self, runner):
        test_abc_name = ("%s.abc" % (path.splitext(self.path)[0])).replace("/", "_")
        cmd = runner.cmd_prefix + [runner.es2panda,
            '--module', '--dump-literal-buffer', '--opt-level=2', '--type-extractor']
        if self.is_dts_test:
            cmd.append("--type-dts-builtin")
        cmd.extend(self.flags)
        cmd.extend(["--output=" + test_abc_name])
        cmd.append(self.path)

        self.log_cmd(cmd)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
        output_str = self.output.split("======> literal array buffer <======")[1]

        if os.path.isfile(test_abc_name):
            os.remove(test_abc_name)

        file_name = path.splitext(self.path)[0]
        if self.is_dts_test:
            expected_path = "%s-expected.txt" % (path.splitext(file_name)[0])
        else:
            expected_path = "%s-expected.txt" % (file_name)
        if not os.path.isfile(expected_path):
            expected_path = path.dirname(path.abspath(__file__)) + "/type_extractor/tsc_expect/%s" % \
                expected_path.split("tests/cases/")[-1]

        try:
            with open(expected_path, 'r') as fp:
                expected = fp.read()
                expected_str = expected.split("======> literal array buffer <======")[1]

            self.passed = expected_str == output_str and process.returncode in [
                0, 1]
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        return self


class TypeExtractorWithAOTTest(Test):
    def __init__(self, test_path, flags, with_running=False, is_project=False):
        Test.__init__(self, test_path, flags)
        self.with_running = with_running
        self.is_project = is_project

    def run_js_vm(self, runner, file_name, test_abc_name):
        expected_path = "%s-expected.txt" % (file_name)
        run_aot_cmd = [runner.ark_js_vm]
        run_aot_cmd.extend(["--aot-file=%s" % file_name])
        run_aot_cmd.extend(["--entry-point=%s" % path.basename(file_name)])
        run_aot_cmd.extend([test_abc_name])
        self.log_cmd(run_aot_cmd)

        process = subprocess.Popen(run_aot_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate(timeout=runner.args.timeout)
        self.output = out.decode("utf-8", errors="ignore") + err.decode("utf-8", errors="ignore")
        try:
            with open(expected_path, 'r') as fp:
                expected = fp.read()
            self.passed = expected == self.output and process.returncode in [0, 1]
        except Exception:
            self.passed = False

        if not self.passed:
            self.error = err.decode("utf-8", errors="ignore")

        if os.path.isfile("%s.an" % (file_name)):
            os.remove("%s.an" % (file_name))
        if os.path.isfile("%s.ai" % (file_name)):
            os.remove("%s.ai" % (file_name))

    def run(self, runner):
        file_name = path.splitext(self.path)[0]
        test_abc_name = ("%s.abc" % path.basename(file_name))
        cmd = runner.cmd_prefix + [runner.es2panda,
            '--module', '--merge-abc', '--opt-level=2', '--type-extractor']
        cmd.extend(self.flags)
        cmd.extend(["--output=" + test_abc_name])
        if self.is_project:
            cmd.append("--extension=ts")
            cmd.append(path.dirname(self.path))
        else:
            cmd.append(self.path)

        self.log_cmd(cmd)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if (err):
            self.passed = False
            self.error = err.decode("utf-8", errors="ignore")
            return self

        ld_library_path = runner.ld_library_path
        os.environ.setdefault("LD_LIBRARY_PATH", ld_library_path)
        aot_abc_cmd = [runner.ark_aot_compiler]
        if self.with_running:
            aot_abc_cmd.extend(["--aot-file=%s" % file_name])
        else:
            aot_abc_cmd.extend(["--compiler-assert-types=true"])
            aot_abc_cmd.extend(["--compiler-opt-type-lowering=false"])
        aot_abc_cmd.extend([test_abc_name])
        self.log_cmd(aot_abc_cmd)

        process = subprocess.Popen(aot_abc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if err:
            self.passed = False
            self.error = err.decode("utf-8", errors="ignore")
        else:
            if self.with_running:
                self.run_js_vm(runner, file_name, test_abc_name)
            else:
                self.passed = True

        if os.path.isfile(test_abc_name):
            os.remove(test_abc_name)
        if os.path.isfile("aot_file.an"):
            os.remove("aot_file.an")
        if os.path.isfile(".ai"):
            os.remove(".ai")

        return self

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

def main():
    args = get_args()

    runners = []

    if args.regression:
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

        runners.append(runner)

        transformer_runner = TransformerRunner(args)
        transformer_runner.add_directory("parser/ts/transformed_cases", "ts",
                                         ["--parse-only", "--module", "--dump-transformed-ast",
                                          "--check-transformed-ast-structure"])

        runners.append(transformer_runner)

    if args.test262:
        runners.append(Test262Runner(args))

    if args.tsc:
        runners.append(TSCRunner(args))

    if args.compiler:
        runner = CompilerRunner(args)
        runner.add_directory("compiler/js", "js", [])
        runner.add_directory("compiler/ts/cases", "ts", [])
        runner.add_directory("compiler/ts/projects", "ts", ["--module"])
        runner.add_directory("compiler/ts/projects", "ts", ["--module", "--merge-abc"])
        runner.add_directory("compiler/dts", "d.ts", ["--module", "--opt-level=0"])
        runner.add_directory("compiler/commonjs", "js", ["--commonjs"])
        runner.add_directory("compiler/recordsource/with-on", "js", ["--record-source"])
        runner.add_directory("compiler/recordsource/with-off", "js", [])

        runners.append(runner)

    if args.hotfix:
        runners.append(HotfixRunner(args))

    if args.hotreload:
        runners.append(HotreloadRunner(args))

    if args.coldfix:
        runners.append(ColdfixRunner(args))

    if args.base64:
        runners.append(Base64Runner(args))

    if args.type_extractor:
        runners.append(TypeExtractorRunner(args))

    if args.bytecode:
        runner = BytecodeRunner(args)
        runner.add_directory("bytecode/commonjs", "js", ["--commonjs", "--dump-assembly"])
        runner.add_directory("bytecode/js", "js", ["--dump-assembly"])

        runners.append(runner)

    failed_tests = 0

    for runner in runners:
        runner.run()
        failed_tests += runner.summarize()

    # TODO: exit 1 when we have failed tests after all tests are fixed
    exit(0)


if __name__ == "__main__":
    main()
