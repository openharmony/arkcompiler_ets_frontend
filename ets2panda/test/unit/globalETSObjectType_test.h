/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PANDA_GLOBAL_ETSOBJECTTYPE_TEST_H
#define PANDA_GLOBAL_ETSOBJECTTYPE_TEST_H

#include "util/options.h"

namespace ark::es2panda::gtests {

class GlobalETSObjectTypeTest : public testing::Test {
public:
    GlobalETSObjectTypeTest()
        : allocator_(std::make_unique<ArenaAllocator>(SpaceType::SPACE_TYPE_COMPILER)),
          publicContext_ {std::make_unique<public_lib::Context>()},
          program_ {parser::Program::NewProgram<varbinder::ETSBinder>(allocator_.get())}
    {
    }

    ~GlobalETSObjectTypeTest() override = default;

    static void SetUpTestCase()
    {
        constexpr auto COMPILER_SIZE = operator""_MB(256ULL);
        mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        PoolManager::Initialize();
    }

    checker::ETSChecker *Checker()
    {
        return &checker_;
    }

    void InitializeChecker(std::string_view fileName, std::string_view src)
    {
        InitializeChecker<parser::ETSParser, varbinder::ETSBinder, checker::ETSChecker, checker::ETSAnalyzer,
                          compiler::ETSCompiler, compiler::ETSGen, compiler::StaticRegSpiller,
                          compiler::ETSFunctionEmitter, compiler::ETSEmitter>(
            Span(test::utils::PandaExecutablePathGetter::Get()), fileName, src, &checker_, &program_);
    }

    template <typename Parser, typename VarBinder, typename Checker, typename Analyzer, typename AstCompiler,
              typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
    void InitializeChecker(Span<const char *const> args, std::string_view fileName, std::string_view src,
                           checker::ETSChecker *checker, parser::Program *program)
    {
        auto options = std::make_unique<ark::es2panda::util::Options>(args[0]);
        if (!options->Parse(args)) {
            std::cerr << options->ErrorMsg() << std::endl;
            return;
        }

        ark::Logger::ComponentMask mask {};
        mask.set(ark::Logger::Component::ES2PANDA);
        ark::Logger::InitializeStdLogging(options->LogLevel(), mask);

        Compiler compiler(options->GetExtension(), options->GetThread());
        SourceFile input(fileName, src, options->IsModule());
        compiler::CompilationUnit unit {input, *options, 0, options->GetExtension()};
        auto getPhases = compiler::GetPhaseList(ScriptExtension::STS);

        program->MarkEntry();
        auto parser = Parser(program, unit.options, static_cast<parser::ParserStatus>(unit.rawParserStatus));
        auto analyzer = Analyzer(checker);
        checker->SetAnalyzer(&analyzer);

        auto *varbinder = program->VarBinder();
        varbinder->SetProgram(program);

        varbinder->SetContext(publicContext_.get());

        auto emitter = Emitter(publicContext_.get());

        auto config = public_lib::ConfigImpl {};
        publicContext_->config = &config;
        publicContext_->config->options = &unit.options;
        publicContext_->sourceFile = &unit.input;
        publicContext_->allocator = allocator_.get();
        publicContext_->parser = &parser;
        publicContext_->checker = checker;
        publicContext_->analyzer = publicContext_->checker->GetAnalyzer();
        publicContext_->emitter = &emitter;
        publicContext_->parserProgram = program;

        parser.ParseScript(unit.input, unit.options.GetCompilationMode() == CompilationMode::GEN_STD_LIB);
        for (auto *phase : getPhases) {
            if (!phase->Apply(publicContext_.get(), program)) {
                return;
            }
        }
    }

    NO_COPY_SEMANTIC(GlobalETSObjectTypeTest);
    NO_MOVE_SEMANTIC(GlobalETSObjectTypeTest);

private:
    std::unique_ptr<ArenaAllocator> allocator_;
    std::unique_ptr<public_lib::Context> publicContext_;
    parser::Program program_;
    checker::ETSChecker checker_;
};

}  // namespace ark::es2panda::gtests
#endif  // PANDA_GLOBAL_ETSOBJECTTYPE_TEST_H
