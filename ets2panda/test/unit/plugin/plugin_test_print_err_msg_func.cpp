/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstddef>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>

#include "public/es2panda_lib.h"
#include "util.h"

// NOLINTBEGIN
namespace {
es2panda_Impl *g_impl = nullptr;
std::string errMsg = "test LogTypeError";
constexpr int LOG_ERROR_FAIL_CODE = 3;  // this error code limits to current file.
}  // namespace

bool PrintErr(const std::string &errStr, es2panda_Context *context)
{
    std::cout << "PROCEED TO " << errStr << " ERROR" << std::endl;
    std::cout << g_impl->ContextErrorMessage(context) << std::endl;
    return false;  // 1: Exit abnormally
}

bool CheckLogTypeError(es2panda_Context *context, es2panda_SourcePosition *pos)
{
    std::stringstream ss;
    std::streambuf *buf = std::cerr.rdbuf();
    std::cerr.rdbuf(ss.rdbuf());
    g_impl->LogTypeError(context, errMsg.c_str(), pos);
    std::cerr.rdbuf(buf);
    CheckForErrors(errMsg, context);
    size_t foundPos = ss.str().find(errMsg);
    if (foundPos == std::string::npos) {
        return PrintErr(errMsg, context);
    }
    ss.clear();
    return true;
}

bool CheckLogWarning(es2panda_Context *context, es2panda_SourcePosition *pos)
{
    std::stringstream ss;
    std::streambuf *buf = std::cerr.rdbuf();
    buf = std::cout.rdbuf();
    std::cout.rdbuf(ss.rdbuf());
    std::string warnMsg = "test LogWarning";
    g_impl->LogWarning(context, warnMsg.c_str(), pos);
    std::cout.rdbuf(buf);
    CheckForErrors(warnMsg, context);
    size_t foundPos = ss.str().find(errMsg);
    foundPos = ss.str().find(warnMsg);
    if (foundPos == std::string::npos) {
        return PrintErr(warnMsg, context);
    }
    ss.clear();
    return true;
}

bool CheckLogSyntaxError(es2panda_Context *context, es2panda_SourcePosition *pos)
{
    std::stringstream ss;
    std::streambuf *buf = std::cerr.rdbuf();
    std::cout.rdbuf(ss.rdbuf());
    std::string synMsg = "test LogSyntaxError";
    g_impl->LogSyntaxError(context, synMsg.c_str(), pos);
    std::cout.rdbuf(buf);
    CheckForErrors(synMsg, context);
    size_t foundPos = ss.str().find(errMsg);
    foundPos = ss.str().find(synMsg);
    if (foundPos == std::string::npos) {
        return PrintErr(synMsg, context);
    }
    ss.clear();
    return true;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return INVALID_ARGC_ERROR_CODE;
    }
    g_impl = GetImpl();
    if (g_impl == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    auto config = g_impl->CreateConfig(argc - 1, argv + 1);
    auto src = std::string("function foo(builder: () => void) {}\nfoo(() => {})");
    auto context = g_impl->CreateContextFromString(config, src.c_str(), argv[argc - 1]);
    if (context == nullptr) {
        std::cerr << "FAILED TO CREATE CONTEXT" << std::endl;
        return NULLPTR_CONTEXT_ERROR_CODE;
    }
    es2panda_SourcePosition *pos = g_impl->CreateSourcePosition(context, 2, 5);
    if (!CheckLogTypeError(context, pos)) {
        return LOG_ERROR_FAIL_CODE;
    }
    if (!CheckLogWarning(context, pos)) {
        return LOG_ERROR_FAIL_CODE;
    }
    if (!CheckLogSyntaxError(context, pos)) {
        return LOG_ERROR_FAIL_CODE;
    }

    return 0;
}

// NOLINTEND
