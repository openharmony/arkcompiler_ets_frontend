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

#include "compilerImpl.h"

#include "plugins/ecmascript/es2panda/compiler/core/compilerContext.h"
#include "plugins/ecmascript/es2panda/compiler/core/compileQueue.h"
#include "plugins/ecmascript/es2panda/compiler/core/compilerImpl.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/compiler/core/JSemitter.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSemitter.h"
#include "plugins/ecmascript/es2panda/parser/parserImpl.h"
#include "plugins/ecmascript/es2panda/parser/JSparser.h"
#include "plugins/ecmascript/es2panda/parser/ASparser.h"
#include "plugins/ecmascript/es2panda/parser/TSparser.h"
#include "plugins/ecmascript/es2panda/parser/ETSparser.h"
#include "plugins/ecmascript/es2panda/parser/program/program.h"
#include "plugins/ecmascript/es2panda/binder/JSBinder.h"
#include "plugins/ecmascript/es2panda/binder/ASBinder.h"
#include "plugins/ecmascript/es2panda/binder/TSBinder.h"
#include "plugins/ecmascript/es2panda/binder/ETSBinder.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ASchecker.h"
#include "plugins/ecmascript/es2panda/checker/JSchecker.h"
#include "plugins/ecmascript/es2panda/es2panda.h"
#include "plugins/ecmascript/es2panda/util/declgenEts2Ts.h"

#include <iostream>
#include <thread>

namespace panda::es2panda::compiler {

void CompilerImpl::HandleContextLiterals(CompilerContext *context)
{
    auto *emitter = context->GetEmitter();

    uint32_t index = 0;
    for (const auto &buff : context->ContextLiterals()) {
        emitter->AddLiteralBuffer(buff, index++);
    }

    emitter->LiteralBufferIndex() += context->ContextLiterals().size();
}

panda::pandasm::Program *CompilerImpl::Emit(CompilerContext *context)
{
    HandleContextLiterals(context);

    queue_.Schedule(context);

    /* Main thread can also be used instead of idling */
    queue_.Consume();
    auto *emitter = context->GetEmitter();
    queue_.Wait([emitter](CompileJob *job) { emitter->AddProgramElement(job->GetProgramElement()); });

    return emitter->Finalize(context->DumpDebugInfo(), Signatures::ETS_GLOBAL);
}

template <typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
static CompilerContext::CodeGenCb MakeCompileJob()
{
    return
        [](CompilerContext *context, binder::FunctionScope *scope, compiler::ProgramElement *program_element) -> void {
            RegSpiller reg_spiller;
            ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
            CodeGen cg(&allocator, &reg_spiller, context, scope, program_element);

            FunctionEmitter func_emitter(&cg, program_element);
            func_emitter.Generate();
        };
}

using EmitCb = std::function<pandasm::Program *(compiler::CompilerContext *)>;

template <typename Parser, typename Binder, typename Checker, typename CodeGen, typename RegSpiller,
          typename FunctionEmitter, typename Emitter>
static pandasm::Program *CreateCompiler(const CompilationUnit &unit, const EmitCb &emit_cb)
{
    ArenaAllocator allocator(SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
    auto program = parser::Program::NewProgram<Binder>(&allocator);
    program.MarkEntry();
    auto parser = Parser(&program, unit.options, static_cast<parser::ParserStatus>(unit.raw_parser_status));
    auto checker = Checker();

    auto *binder = program.Binder();
    binder->SetProgram(&program);

    CompilerContext context(binder, &checker, unit.options,
                            MakeCompileJob<CodeGen, RegSpiller, FunctionEmitter, Emitter>());
    binder->SetCompilerContext(&context);

    auto emitter = Emitter(&context);
    context.SetEmitter(&emitter);

    parser.ParseScript(unit.input, unit.options.compilation_mode == CompilationMode::GEN_STD_LIB);

    if (!checker.StartChecker(binder, unit.options)) {
        return nullptr;
    }

    if constexpr (std::is_same_v<Checker, checker::ETSChecker>) {
        if (!unit.options.ts_decl_out.empty() &&
            !util::GenerateTsDeclarations(&checker, &program, unit.options.ts_decl_out)) {
            return nullptr;
        }
    }

    emitter.GenAnnotation();

    return emit_cb(&context);
}

pandasm::Program *CompilerImpl::Compile(const CompilationUnit &unit)
{
    auto emit_cb = [this](CompilerContext *context) -> pandasm::Program * { return Emit(context); };

    switch (unit.ext) {
        case ScriptExtension::TS: {
            return CreateCompiler<parser::TSParser, binder::TSBinder, checker::TSChecker, compiler::PandaGen,
                                  compiler::DynamicRegSpiller, compiler::JSFunctionEmitter, compiler::JSEmitter>(
                unit, emit_cb);
        }
        case ScriptExtension::AS: {
            return CreateCompiler<parser::ASParser, binder::ASBinder, checker::ASChecker, compiler::PandaGen,
                                  compiler::DynamicRegSpiller, compiler::JSFunctionEmitter, compiler::JSEmitter>(
                unit, emit_cb);
        }
        case ScriptExtension::ETS: {
            return CreateCompiler<parser::ETSParser, binder::ETSBinder, checker::ETSChecker, compiler::ETSGen,
                                  compiler::StaticRegSpiller, compiler::ETSFunctionEmitter, compiler::ETSEmitter>(
                unit, emit_cb);
        }
        case ScriptExtension::JS: {
            return CreateCompiler<parser::JSParser, binder::JSBinder, checker::JSChecker, compiler::PandaGen,
                                  compiler::DynamicRegSpiller, compiler::JSFunctionEmitter, compiler::JSEmitter>(
                unit, emit_cb);
        }
        default: {
            UNREACHABLE();
            return nullptr;
        }
    }
}

void CompilerImpl::DumpAsm(const panda::pandasm::Program *prog)
{
    Emitter::DumpAsm(prog);
}
}  // namespace panda::es2panda::compiler
