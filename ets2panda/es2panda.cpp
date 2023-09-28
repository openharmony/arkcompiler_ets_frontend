/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "es2panda.h"

#include "plugins/ecmascript/es2panda/compiler/core/compilerImpl.h"

#include <iostream>
#include <thread>

namespace panda::es2panda {
constexpr size_t DEFAULT_THREAD_COUNT = 2;

template <class T>
T DirName(T const &path, T const &delims = panda::os::file::File::GetPathDelim())
{
    std::size_t pos = path.find_last_of(delims);

    if (pos == std::string::npos) {
        return "./";
    }

    if (pos == 0) {
        return delims;
    }

    std::string_view dir_path = path.substr(0, pos);
    if (dir_path.compare(".") == 0 || dir_path.compare("..") == 0) {
        return path.substr(0, pos + 1);
    }

    return path.substr(0, pos);
}

SourceFile::SourceFile(std::string_view fn, std::string_view s) : file_name(fn), file_path(DirName(fn)), source(s) {}

SourceFile::SourceFile(std::string_view fn, std::string_view s, bool m)
    : file_name(fn), file_path(DirName(fn)), source(s), is_module(m)
{
}

SourceFile::SourceFile(std::string_view fn, std::string_view s, std::string_view rp, bool m)
    : file_name(fn), file_path(DirName(fn)), source(s), resolved_path(DirName(rp)), is_module(m)
{
}

Compiler::Compiler(ScriptExtension ext) : Compiler(ext, DEFAULT_THREAD_COUNT) {}

Compiler::Compiler(ScriptExtension ext, size_t thread_count)
    : compiler_(new compiler::CompilerImpl(thread_count)), ext_(ext)
{
}

Compiler::~Compiler()
{
    delete compiler_;
}

pandasm::Program *Compiler::Compile(const SourceFile &input, const CompilerOptions &options, uint32_t parse_status)
{
    try {
        return compiler_->Compile(compiler::CompilationUnit {input, options, parse_status, ext_});
    } catch (const class Error &e) {
        error_ = e;
        return nullptr;
    }
}

void Compiler::DumpAsm(const pandasm::Program *prog)
{
    compiler::CompilerImpl::DumpAsm(prog);
}
}  // namespace panda::es2panda
