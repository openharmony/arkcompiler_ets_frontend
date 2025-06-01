/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_TEST_UTILS_CHECKER_TEST_H
#define ES2PANDA_TEST_UTILS_CHECKER_TEST_H

#include "compiler/core/compilerImpl.h"
#include "compiler/lowering/phase.h"
#include "panda_executable_path_getter.h"
#include "compiler/core/regSpiller.h"
#include "compiler/core/ETSemitter.h"
#include "checker/ETSAnalyzer.h"
#include "util/options.h"
#include "util/diagnosticEngine.h"
#include <gtest/gtest.h>

namespace ir_alias = ark::es2panda::ir;
namespace checker_alias = ark::es2panda::checker;
namespace varbinder_alias = ark::es2panda::varbinder;
namespace plib_alias = ark::es2panda::public_lib;
namespace parser_alias = ark::es2panda::parser;
namespace compiler_alias = ark::es2panda::compiler;
namespace util_alias = ark::es2panda::util;
namespace test::utils {

class CheckerTest : public testing::Test {
public:
    CheckerTest()
        : allocator_(std::make_unique<ark::ArenaAllocator>(ark::SpaceType::SPACE_TYPE_COMPILER)),
          publicContext_ {std::make_unique<plib_alias::Context>()},
          program_ {parser_alias::Program::NewProgram<varbinder_alias::ETSBinder>(allocator_.get())},
          es2pandaPath_ {PandaExecutablePathGetter::Get()[0]},
          checker_(diagnosticEngine_)
    {
    }
    ~CheckerTest() override = default;
    static void SetUpTestCase()
    {
        ark::mem::MemConfig::Initialize(0, 0, ark::es2panda::COMPILER_SIZE, 0, 0, 0);
        ark::PoolManager::Initialize();
    }

    checker_alias::ETSChecker *Checker()
    {
        return &checker_;
    }

    ark::ArenaAllocator *Allocator()
    {
        return allocator_.get();
    }

    parser_alias::Program *Program()
    {
        return &program_;
    }
    checker_alias::Type *FindClassType(varbinder_alias::ETSBinder *varbinder, std::string_view className);

    checker_alias::Type *FindTypeAlias(checker_alias::ETSChecker *checker, std::string_view aliasName);

    void InitializeChecker(std::string_view fileName, std::string_view src)
    {
        auto es2pandaPathPtr = es2pandaPath_.c_str();
        ASSERT(es2pandaPathPtr);

        InitializeChecker<parser_alias::ETSParser, varbinder_alias::ETSBinder, checker_alias::ETSChecker,
                          checker_alias::ETSAnalyzer, compiler_alias::ETSCompiler, compiler_alias::ETSGen,
                          compiler_alias::StaticRegSpiller, compiler_alias::ETSFunctionEmitter,
                          compiler_alias::ETSEmitter>(&es2pandaPathPtr, fileName, src, &checker_, &program_);
    }

    template <typename Parser, typename VarBinder, typename Checker, typename Analyzer, typename AstCompiler,
              typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
    void InitializeChecker(char const *const *argv, std::string_view fileName, std::string_view src,
                           checker_alias::ETSChecker *checker, parser_alias::Program *program)
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        auto options = std::make_unique<util_alias::Options>(argv[0], diagnosticEngine_);
        if (!options->Parse(ark::Span(argv, 1))) {
            return;
        }

        ark::Logger::ComponentMask mask {};
        mask.set(ark::Logger::Component::ES2PANDA);
        ark::Logger::InitializeStdLogging(options->LogLevel(), mask);

        ark::es2panda::Compiler compiler(options->GetExtension(), options->GetThread());
        ark::es2panda::SourceFile input(fileName, src, options->IsModule());
        compiler_alias::CompilationUnit unit {input, *options, 0, options->GetExtension(), diagnosticEngine_};
        auto parser = Parser(program, unit.options, diagnosticEngine_,
                             static_cast<parser_alias::ParserStatus>(unit.rawParserStatus));
        auto analyzer = Analyzer(checker);
        checker->SetAnalyzer(&analyzer);

        auto *varbinder = program->VarBinder();
        varbinder->SetProgram(program);

        varbinder->SetContext(publicContext_.get());

        auto emitter = Emitter(publicContext_.get());
        auto phaseManager = compiler_alias::PhaseManager(unit.ext, allocator_.get());

        auto config = plib_alias::ConfigImpl {};
        publicContext_->config = &config;
        publicContext_->config->options = &unit.options;
        publicContext_->sourceFile = &unit.input;
        publicContext_->allocator = allocator_.get();
        publicContext_->parser = &parser;
        publicContext_->checker = checker;
        publicContext_->analyzer = publicContext_->checker->GetAnalyzer();
        publicContext_->emitter = &emitter;
        publicContext_->parserProgram = program;
        publicContext_->diagnosticEngine = &diagnosticEngine_;
        publicContext_->phaseManager = &phaseManager;
        parser.ParseScript(unit.input,
                           unit.options.GetCompilationMode() == ark::es2panda::CompilationMode::GEN_STD_LIB);
        while (auto phase = publicContext_->phaseManager->NextPhase()) {
            if (!phase->Apply(publicContext_.get(), program)) {
                return;
            }
        }
    }
    NO_COPY_SEMANTIC(CheckerTest);
    NO_MOVE_SEMANTIC(CheckerTest);

private:
    std::unique_ptr<ark::ArenaAllocator> allocator_;
    std::unique_ptr<plib_alias::Context> publicContext_;
    parser_alias::Program program_;
    std::string es2pandaPath_;
    util_alias::DiagnosticEngine diagnosticEngine_;
    checker_alias::ETSChecker checker_;
};

}  // namespace test::utils

#endif  // ES2PANDA_TEST_UTILS_CHECKER_TEST_H
