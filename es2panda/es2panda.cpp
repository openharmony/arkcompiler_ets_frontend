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
#include <compiler/core/emitter/emitter.h>
#include <parser/parserImpl.h>
#include <parser/program/program.h>
#include <parser/transformer/transformer.h>
#include <typescript/checker.h>
#include <util/helpers.h>

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
    if (parser_->Extension() == ScriptExtension::TS) {
        transformer_ = std::make_unique<parser::Transformer>(parser_->Allocator());
    }
}

Compiler::~Compiler()
{
    delete parser_;
    delete compiler_;
}

panda::pandasm::Program *CreateJsonContentProgram(std::string src, std::string rname, util::Hotfix *hotfixHelper)
{
    panda::es2panda::compiler::CompilerContext context(nullptr, false, false, false, false, true,
                                                       src, "", util::StringView(rname), hotfixHelper);
    return context.GetEmitter()->Finalize(false, nullptr);
}

panda::pandasm::Program *Compiler::Compile(const SourceFile &input, const CompilerOptions &options,
    util::SymbolTable *symbolTable)
{
    /* TODO(dbatyai): pass string view */
    std::string fname(input.fileName);
    std::string src(input.source);
    std::string rname(input.recordName);
    std::string sourcefile(input.sourcefile);
    std::string pkgName(input.pkgName);
    parser::ScriptKind kind(input.scriptKind);

    auto *hotfixHelper = InitHotfixHelper(input, options, symbolTable);

    if (fname.substr(fname.find_last_of(".") + 1) == "json") {
        return CreateJsonContentProgram(src, rname, hotfixHelper);
    }

    try {
        auto ast = parser_->Parse(fname, src, rname, kind);
        ast.Binder()->SetProgram(&ast);

        if (options.dumpAst) {
            std::cout << ast.Dump() << std::endl;
        }

        if (ast.Extension() == ScriptExtension::TS && options.enableTypeCheck) {
            ArenaAllocator localAllocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
            auto checker = std::make_unique<checker::Checker>(&localAllocator, ast.Binder());
            checker->StartChecker();
        }

        if (ast.Extension() == ScriptExtension::TS) {
            transformer_->Transform(&ast);
            ast.Binder()->IdentifierAnalysis(binder::ResolveBindingFlags::ALL);
        }

        if (options.parseOnly) {
            return nullptr;
        }

        std::string debugInfoSourceFile = options.debugInfoSourceFile.empty() ?
                                          sourcefile : options.debugInfoSourceFile;
        auto *prog = compiler_->Compile(&ast, options, debugInfoSourceFile, pkgName);

        CleanHotfixHelper(hotfixHelper);
        return prog;
    } catch (const class Error &e) {
        error_ = e;

        CleanHotfixHelper(hotfixHelper);
        return nullptr;
    }
}

util::Hotfix *Compiler::InitHotfixHelper(const SourceFile &input, const CompilerOptions &options,
                                         util::SymbolTable *symbolTable)
{
    bool needDumpSymbolFile = !options.hotfixOptions.dumpSymbolTable.empty();
    bool needGeneratePatch = options.hotfixOptions.generatePatch && !options.hotfixOptions.symbolTable.empty();
    util::Hotfix *hotfixHelper = nullptr;
    if (symbolTable && (needDumpSymbolFile || needGeneratePatch)) {
        hotfixHelper = new util::Hotfix(needDumpSymbolFile, needGeneratePatch, input.recordName, symbolTable);
        parser_->AddHotfixHelper(hotfixHelper);
        compiler_->AddHotfixHelper(hotfixHelper);
    }
    return hotfixHelper;
}

void Compiler::CleanHotfixHelper(const util::Hotfix *hotfixHelper)
{
    if (hotfixHelper) {
        delete hotfixHelper;
        hotfixHelper = nullptr;
    }
}

void Compiler::DumpAsm(const panda::pandasm::Program *prog)
{
    compiler::CompilerImpl::DumpAsm(prog);
}

static bool ReadFileToBuffer(const std::string &file, std::stringstream &ss)
{
    std::ifstream inputStream(file, std::ios::binary);
    if (inputStream.fail()) {
        std::cerr << "Failed to read file to buffer: " << file << std::endl;
        return false;
    }
    ss << inputStream.rdbuf();
    return true;
}

void Compiler::SelectCompileFile(CompilerOptions &options,
    std::map<std::string, panda::es2panda::util::ProgramCache*> *cacheProgs,
    std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
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
            auto *cache = allocator->New<util::ProgramCache>(it->second->hashCode, it->second->program);
            progsInfo.insert({input.fileName, cache});
        } else {
            input.hash = hash;
            inputList.push_back(input);
        }
    }
    options.sourceFiles = inputList;
}

int Compiler::CompileFiles(CompilerOptions &options,
    std::map<std::string, panda::es2panda::util::ProgramCache*> *cacheProgs,
    std::map<std::string, panda::es2panda::util::ProgramCache*> &progsInfo,
    panda::ArenaAllocator *allocator)
{
    util::SymbolTable *symbolTable = nullptr;
    if (!options.hotfixOptions.symbolTable.empty() || !options.hotfixOptions.dumpSymbolTable.empty()) {
        symbolTable = new util::SymbolTable(options.hotfixOptions.symbolTable, options.hotfixOptions.dumpSymbolTable);
        if (!symbolTable->Initialize()) {
            std::cerr << "Exits due to hot fix initialize failed!" << std::endl;
            return 1;
        }
    }

    SelectCompileFile(options, cacheProgs, progsInfo, allocator);

    bool failed = false;
    auto queue = new compiler::CompileFileQueue(options.fileThreadCount, &options, progsInfo, symbolTable, allocator);

    try {
        queue->Schedule();
        queue->Consume();
        queue->Wait();
    } catch (const class Error &e) {
        failed = true;
    }

    delete queue;
    queue = nullptr;

    if (symbolTable) {
        delete symbolTable;
        symbolTable = nullptr;
    }

    return failed ? 1 : 0;
}

panda::pandasm::Program *Compiler::CompileFile(const CompilerOptions &options, SourceFile *src,
                                               util::SymbolTable *symbolTable)
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

    auto *program = Compile(*src, options, symbolTable);
    if (!program) {
        const auto &err = GetError();

        if (err.Message().empty() && options.parseOnly) {
            return nullptr;
        }

        std::cerr << err.TypeString() << ": " << err.Message();
        std::cerr << " [" << util::Helpers::BaseName(src->fileName) << ":"
                  << err.Line() << ":" << err.Col() << "]" << std::endl;
        throw err;
    }
    return program;
}

}  // namespace panda::es2panda
