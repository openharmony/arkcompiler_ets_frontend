/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PUBLIC_PUBLIC_H
#define ES2PANDA_PUBLIC_PUBLIC_H

#include "public/es2panda_lib.h"

#include "assembler/assembly-program.h"
#include "libpandabase/mem/arena_allocator.h"

#include "compiler/core/compileQueue.h"
#include "parser/ETSparser.h"
#include "checker/checker.h"
#include "compiler/core/emitter.h"

namespace ark::es2panda::util {
class Options;
}  // namespace ark::es2panda::util

namespace ark::es2panda::compiler {
class PhaseManager;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::public_lib {
struct ConfigImpl {
    const util::Options *options = nullptr;
    util::DiagnosticEngine *diagnosticEngine = nullptr;
    std::vector<diagnostic::DiagnosticKind> diagnosticKindStorage;
};

struct Context {
    using CodeGenCb =
        std::function<void(public_lib::Context *context, varbinder::FunctionScope *, compiler::ProgramElement *)>;

    ConfigImpl *config = nullptr;
    std::string sourceFileName;
    std::string input;
    SourceFile const *sourceFile = nullptr;
    ArenaAllocator *allocator = nullptr;
    compiler::CompileQueue *queue = nullptr;
    std::vector<util::Plugin> const *plugins = nullptr;
    std::vector<compiler::LiteralBuffer> contextLiterals;
    CodeGenCb codeGenCb;
    compiler::PhaseManager *phaseManager = nullptr;

    parser::Program *parserProgram = nullptr;
    parser::ParserImpl *parser = nullptr;
    checker::Checker *checker = nullptr;
    checker::SemanticAnalyzer *analyzer = nullptr;
    compiler::Emitter *emitter = nullptr;
    pandasm::Program *program = nullptr;
    util::DiagnosticEngine *diagnosticEngine = nullptr;

    es2panda_ContextState state = ES2PANDA_STATE_NEW;
    std::string errorMessage;
    lexer::SourcePosition errorPos;
};
}  // namespace ark::es2panda::public_lib

#endif
