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

#include <compiler/core/compileQueue.h>
#include <compiler/core/compilerContext.h>
#include <compiler/core/compilerImpl.h>
#include <parser/parserImpl.h>
#include <parser/program/program.h>

#include <libpandabase/utils/hash.h>

#include <iostream>
#include <thread>

namespace panda::es2panda {
// Compiler

constexpr size_t DEFAULT_THREAD_COUNT = 2;

Compiler::Compiler(ScriptExtension ext) : Compiler(ext, DEFAULT_THREAD_COUNT) {}

Compiler::Compiler(ScriptExtension ext, size_t threadCount)
    : parser_(new parser::ParserImpl(ext)), compiler_(new compiler::CompilerImpl(threadCount))
{
}

Compiler::~Compiler()
{
    delete parser_;
    delete compiler_;
}

panda::pandasm::Program *Compiler::Compile(const SourceFile &input, const CompilerOptions &options)
{
    /* TODO(dbatyai): pass string view */
    std::string fname(input.fileName);
    std::string src(input.source);
    std::string rname(input.recordName);
    parser::ScriptKind kind(input.scriptKind);

    try {
        auto ast = parser_->Parse(fname, src, rname, kind);

        if (options.dumpAst) {
            std::cout << ast.Dump() << std::endl;
        }

        if (options.parseOnly) {
            return nullptr;
        }

        std::string debugInfoSourceFile = options.debugInfoSourceFile.empty() ? fname : options.debugInfoSourceFile;
        auto *prog = compiler_->Compile(&ast, options, debugInfoSourceFile);

        return prog;
    } catch (const class Error &e) {
        error_ = e;
        return nullptr;
    }
}

void Compiler::DumpAsm(const panda::pandasm::Program *prog)
{
    compiler::CompilerImpl::DumpAsm(prog);
}

static bool ReadFileToBuffer(const std::string &file, std::stringstream &ss)
{
    std::ifstream inputStream(file);
    if (inputStream.fail()) {
        std::cerr << "Failed to read file to buffer: " << file << std::endl;
        return false;
    }
    ss << inputStream.rdbuf();
    return true;
}

void Compiler::SelectCompileFile(CompilerOptions &options,
    std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> *cacheProgs,
    std::vector<panda::pandasm::Program *> &progs,
    std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
    panda::ArenaAllocator *allocator)
{
    if (cacheProgs == nullptr) {
        return;
    }

    auto fullList = options.sourceFiles;
    std::vector<SourceFile> inputList;

    for (auto &input: fullList) {
        if (input.fileName.empty()) {
            // base64 source
            inputList.push_back(input);
            continue;
        }

        std::stringstream ss;
        if (!ReadFileToBuffer(input.fileName, ss)) {
            continue;
        }

        uint32_t hash = GetHash32String(reinterpret_cast<const uint8_t *>(ss.str().c_str()));

        auto it = cacheProgs->find(input.fileName);
        if (it != cacheProgs->end() && hash == it->second->hashCode) {
            progs.push_back(it->second->program);
            auto *cache = allocator->New<util::ProgramCache>(it->second->hashCode, it->second->program);
            progsInfo.insert({input.fileName, cache});
        } else {
            input.hash = hash;
            inputList.push_back(input);
        }
    }
    options.sourceFiles = inputList;
}

void Compiler::CompileFiles(CompilerOptions &options,
    std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> *cacheProgs,
    std::vector<panda::pandasm::Program *> &progs,
    std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
    panda::ArenaAllocator *allocator)
{
    SelectCompileFile(options, cacheProgs, progs, progsInfo, allocator);

    auto queue = new compiler::CompileFileQueue(options.fileThreadCount, &options, progs, progsInfo, allocator);

    queue->Schedule();
    queue->Consume();
    queue->Wait();

    delete queue;
}

panda::pandasm::Program *Compiler::CompileFile(CompilerOptions &options, SourceFile *src)
{
    std::string buffer;
    if (src->source.empty()) {
        std::stringstream ss;
        if (!ReadFileToBuffer(src->fileName, ss)) {
            return nullptr;
        }
        buffer = ss.str();
        src->source = buffer;

        if (src->hash == 0) {
            src->hash = GetHash32String(reinterpret_cast<const uint8_t *>(buffer.c_str()));
        }
    }

    auto *program = Compile(*src, options);
    if (!program) {
        const auto &err = GetError();

        if (err.Message().empty() && options.parseOnly) {
            return nullptr;
        }

        std::cerr << err.TypeString() << ": " << err.Message();
        std::cerr << " [" << src->fileName << ":" << err.Line() << ":" << err.Col() << "]" << std::endl;
        return nullptr;
    }
    return program;
}

}  // namespace panda::es2panda
