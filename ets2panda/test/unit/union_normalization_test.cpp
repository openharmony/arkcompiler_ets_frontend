/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <algorithm>

#include "checker/ETSAnalyzer.h"
#include "checker/ETSchecker.h"
#include "compiler/core/compilerImpl.h"
#include "compiler/core/ETSCompiler.h"
#include "compiler/core/ETSemitter.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regSpiller.h"
#include "compiler/lowering/phase.h"
#include "es2panda.h"
#include "mem/arena_allocator.h"
#include "mem/pool_manager.h"
#include "public/public.h"
#include "util/arktsconfig.h"
#include "util/generateBin.h"
#include "varbinder/ETSBinder.h"

namespace panda::es2panda {

class UnionNormalizationTest : public testing::Test {
public:
    UnionNormalizationTest()
    {
        allocator_ = std::make_unique<ArenaAllocator>(SpaceType::SPACE_TYPE_COMPILER);
        public_context_ = std::make_unique<public_lib::Context>();
    }

    ~UnionNormalizationTest() override = default;

    static void SetUpTestCase()
    {
        constexpr auto COMPILER_SIZE = operator""_MB(256ULL);
        mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        PoolManager::Initialize();
    }

    ArenaAllocator *Allocator()
    {
        return allocator_.get();
    }

    void InitializeChecker(const char **argv, std::string_view file_name, std::string_view src,
                           checker::ETSChecker *checker, parser::Program *program)
    {
        InitializeChecker<parser::ETSParser, varbinder::ETSBinder, checker::ETSChecker, checker::ETSAnalyzer,
                          compiler::ETSCompiler, compiler::ETSGen, compiler::StaticRegSpiller,
                          compiler::ETSFunctionEmitter, compiler::ETSEmitter>(argv, file_name, src, checker, program);
    }

    template <typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter, typename AstCompiler>
    compiler::CompilerContext::CodeGenCb MakeCompileJob()
    {
        return [this](compiler::CompilerContext *context, varbinder::FunctionScope *scope,
                      compiler::ProgramElement *program_element) -> void {
            RegSpiller reg_spiller;
            AstCompiler astcompiler;
            CodeGen cg(allocator_.get(), &reg_spiller, context, scope, program_element, &astcompiler);
            FunctionEmitter func_emitter(&cg, program_element);
            func_emitter.Generate();
        };
    }

    template <typename Parser, typename VarBinder, typename Checker, typename Analyzer, typename AstCompiler,
              typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
    void InitializeChecker(const char **argv, std::string_view file_name, std::string_view src,
                           checker::ETSChecker *checker, parser::Program *program)
    {
        auto options = std::make_unique<panda::es2panda::util::Options>();
        if (!options->Parse(1, argv)) {
            std::cerr << options->ErrorMsg() << std::endl;
            return;
        }

        panda::Logger::ComponentMask mask {};
        mask.set(panda::Logger::Component::ES2PANDA);
        panda::Logger::InitializeStdLogging(panda::Logger::LevelFromString(options->LogLevel()), mask);

        Compiler compiler(options->Extension(), options->ThreadCount());
        SourceFile input(file_name, src, options->ParseModule());
        compiler::CompilationUnit unit {input, options->CompilerOptions(), 0, options->Extension()};
        auto get_phases = compiler::GetPhaseList(ScriptExtension::ETS);

        program->MarkEntry();
        auto parser = Parser(program, unit.options, static_cast<parser::ParserStatus>(unit.raw_parser_status));
        auto analyzer = Analyzer(checker);
        checker->SetAnalyzer(&analyzer);

        auto *varbinder = program->VarBinder();
        varbinder->SetProgram(program);

        compiler::CompilerContext context(varbinder, checker, unit.options,
                                          MakeCompileJob<CodeGen, RegSpiller, FunctionEmitter, Emitter, AstCompiler>());
        varbinder->SetCompilerContext(&context);

        auto emitter = Emitter(&context);
        context.SetEmitter(&emitter);
        context.SetParser(&parser);

        public_context_->source_file = &unit.input;
        public_context_->allocator = allocator_.get();
        public_context_->parser = &parser;
        public_context_->checker = context.Checker();
        public_context_->analyzer = public_context_->checker->GetAnalyzer();
        public_context_->compiler_context = &context;
        public_context_->emitter = context.GetEmitter();

        parser.ParseScript(unit.input, unit.options.compilation_mode == CompilationMode::GEN_STD_LIB);
        if constexpr (std::is_same_v<Parser, parser::ETSParser> && std::is_same_v<VarBinder, varbinder::ETSBinder>) {
            reinterpret_cast<varbinder::ETSBinder *>(varbinder)->FillResolvedImportPathes(
                parser.ResolvedParsedSourcesMap(), allocator_.get());
        }
        for (auto *phase : get_phases) {
            if (!phase->Apply(public_context_.get(), program)) {
                return;
            }
        }
    }

    static checker::Type *FindClassType(varbinder::ETSBinder *varbinder, std::string_view class_name)
    {
        auto class_defs = varbinder->AsETSBinder()->GetRecordTable()->ClassDefinitions();
        auto base_class = std::find_if(class_defs.begin(), class_defs.end(), [class_name](ir::ClassDefinition *cdef) {
            return cdef->Ident()->Name().Is(class_name);
        });
        if (base_class == class_defs.end()) {
            return nullptr;
        }
        return (*base_class)->TsType();
    }

    static checker::Type *FindTypeAlias(checker::ETSChecker *checker, std::string_view alias_name)
    {
        auto *found_var =
            checker->Scope()->FindLocal(alias_name, varbinder::ResolveBindingOptions::ALL)->AsLocalVariable();
        if (found_var == nullptr) {
            return nullptr;
        }
        return found_var->Declaration()->Node()->AsTSTypeAliasDeclaration()->TypeAnnotation()->TsType();
    }

    NO_COPY_SEMANTIC(UnionNormalizationTest);
    NO_MOVE_SEMANTIC(UnionNormalizationTest);

protected:
    static constexpr uint8_t SIZE2 = 2;
    static constexpr uint8_t SIZE3 = 3;
    static constexpr uint8_t IDX0 = 0;
    static constexpr uint8_t IDX1 = 1;
    static constexpr uint8_t IDX2 = 2;

private:
    std::unique_ptr<ArenaAllocator> allocator_;
    std::unique_ptr<public_lib::Context> public_context_;
};

TEST_F(UnionNormalizationTest, UnionWithObject)
{
    // Test normalization: int | Object | string ==> Object
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    ArenaVector<checker::Type *> union_constituents(checker.Allocator()->Adapter());
    union_constituents.emplace_back(checker.GlobalIntType());
    union_constituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalETSObjectType());
    union_constituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalETSStringBuiltinType());

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type = checker.CreateETSUnionType(std::move(union_constituents));
    ASSERT_NE(normalized_type, nullptr);
    ASSERT_TRUE(normalized_type->IsETSObjectType());
    ASSERT_EQ(normalized_type, checker.GlobalETSObjectType());
}

TEST_F(UnionNormalizationTest, UnionWithIdenticalTypes1)
{
    // Test normalization: number | Base | string | number ==> number | Base | string
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "class Base {}", &checker, &program);

    auto *const base_type = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(base_type, nullptr);

    ArenaVector<checker::Type *> union_constituents(checker.Allocator()->Adapter());
    union_constituents.emplace_back(checker.GlobalDoubleType());
    union_constituents.emplace_back(base_type);
    union_constituents.emplace_back(checker.GlobalBuiltinETSStringType());
    union_constituents.emplace_back(checker.GlobalDoubleType());

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type = checker.CreateETSUnionType(std::move(union_constituents));
    ASSERT_NE(normalized_type, nullptr);
    ASSERT_TRUE(normalized_type->IsETSUnionType());
    auto *const union_type = normalized_type->AsETSUnionType();
    ASSERT_EQ(union_type->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX0), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX1), base_type);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX2), checker.GlobalBuiltinETSStringType());
}

TEST_F(UnionNormalizationTest, UnionWithIdenticalTypes2)
{
    // Test normalization: Base | int | Base | double | short | number ==> Base | number
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "class Base {}", &checker, &program);

    auto *const base_type = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(base_type, nullptr);

    ArenaVector<checker::Type *> union_constituents(checker.Allocator()->Adapter());
    union_constituents.emplace_back(base_type);
    union_constituents.emplace_back(checker.GlobalIntType());
    union_constituents.emplace_back(base_type);
    union_constituents.emplace_back(checker.GlobalDoubleType());
    union_constituents.emplace_back(checker.GlobalShortType());
    union_constituents.emplace_back(checker.GlobalDoubleType());

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type = checker.CreateETSUnionType(std::move(union_constituents));
    ASSERT_NE(normalized_type, nullptr);
    ASSERT_TRUE(normalized_type->IsETSUnionType());
    auto *const union_type = normalized_type->AsETSUnionType();
    ASSERT_EQ(union_type->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX0), base_type);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithNumeric1)
{
    // Test normalization: boolean | int | double | short ==> boolean | double
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    ArenaVector<checker::Type *> union_constituents(checker.Allocator()->Adapter());
    union_constituents.emplace_back(checker.GlobalETSBooleanType());
    union_constituents.emplace_back(checker.GlobalIntType());
    union_constituents.emplace_back(checker.GlobalDoubleType());
    union_constituents.emplace_back(checker.GlobalShortType());

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type = checker.CreateETSUnionType(std::move(union_constituents));
    ASSERT_NE(normalized_type, nullptr);
    ASSERT_TRUE(normalized_type->IsETSUnionType());
    auto *const union_type = normalized_type->AsETSUnionType();
    ASSERT_EQ(union_type->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX0), checker.GetGlobalTypesHolder()->GlobalETSBooleanBuiltinType());
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithNumeric2)
{
    // Test normalization: string | int | Base | double | short ==> string | Base | double
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "class Base {}", &checker, &program);

    auto *const base_type = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(base_type, nullptr);

    ArenaVector<checker::Type *> union_constituents(checker.Allocator()->Adapter());
    union_constituents.emplace_back(checker.GlobalBuiltinETSStringType());
    union_constituents.emplace_back(checker.GlobalIntType());
    union_constituents.emplace_back(base_type);
    union_constituents.emplace_back(checker.GlobalDoubleType());
    union_constituents.emplace_back(checker.GlobalShortType());

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type = checker.CreateETSUnionType(std::move(union_constituents));
    ASSERT_NE(normalized_type, nullptr);
    ASSERT_TRUE(normalized_type->IsETSUnionType());
    auto *const union_type = normalized_type->AsETSUnionType();
    ASSERT_EQ(union_type->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX0), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX1), base_type);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX2), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithSubTypes)
{
    // Test 4 cases of normalization
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    static constexpr std::string_view SRC =
        "\
        class Base {}\
        class Derived1 extends Base {}\
        class Derived2 extends Base {}\
        ";
    InitializeChecker(&argv, "_.ets", SRC, &checker, &program);

    auto *const base_type = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(base_type, nullptr);
    auto *const derived1_type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived1");
    ASSERT_NE(derived1_type, nullptr);
    auto *const derived2_type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived2");
    ASSERT_NE(derived2_type, nullptr);

    // Test normalization: Derived1 | Base ==> Base
    ArenaVector<checker::Type *> union_constituents1(checker.Allocator()->Adapter());
    union_constituents1.emplace_back(derived1_type);
    union_constituents1.emplace_back(base_type);

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type1 = checker.CreateETSUnionType(std::move(union_constituents1));
    ASSERT_NE(normalized_type1, nullptr);
    ASSERT_TRUE(normalized_type1->IsETSObjectType());
    ASSERT_EQ(normalized_type1, base_type);

    // Test normalization: Base | Derived2 ==> Base
    ArenaVector<checker::Type *> union_constituents2(checker.Allocator()->Adapter());
    union_constituents2.emplace_back(base_type);
    union_constituents2.emplace_back(derived2_type);

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type2 = checker.CreateETSUnionType(std::move(union_constituents2));
    ASSERT_NE(normalized_type2, nullptr);
    ASSERT_TRUE(normalized_type2->IsETSObjectType());
    ASSERT_EQ(normalized_type2, base_type);

    // Test normalization: Derived1 | Derived2 ==> Derived1 | Derived2
    ArenaVector<checker::Type *> union_constituents3(checker.Allocator()->Adapter());
    union_constituents3.emplace_back(derived1_type);
    union_constituents3.emplace_back(derived2_type);

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type3 = checker.CreateETSUnionType(std::move(union_constituents3));
    ASSERT_NE(normalized_type3, nullptr);
    auto *const union_type = normalized_type3->AsETSUnionType();
    ASSERT_EQ(union_type->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX0), derived1_type);
    ASSERT_EQ(union_type->ConstituentTypes().at(IDX1), derived2_type);

    // Test normalization: Derived2 | Base | Derived1 ==> Base
    ArenaVector<checker::Type *> union_constituents4(checker.Allocator()->Adapter());
    union_constituents4.emplace_back(derived1_type);
    union_constituents4.emplace_back(base_type);
    union_constituents4.emplace_back(derived2_type);

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type4 = checker.CreateETSUnionType(std::move(union_constituents4));
    ASSERT_NE(normalized_type4, nullptr);
    ASSERT_TRUE(normalized_type4->IsETSObjectType());
    ASSERT_EQ(normalized_type4, base_type);
}

TEST_F(UnionNormalizationTest, UnionLinearization)
{
    // Test 3 cases of normalization
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    static constexpr std::string_view SRC =
        "\
        class Base {}\
        class Derived1 extends Base {}\
        class Derived2 extends Base {}\
        type UT = int | string\
        \
        type UT1 = int | (int | string) | number\
        type UT2 = int | UT | number\
        type UT3 = int | (Derived2 | Base) | Derived1 | (string | number | short) | (int | string)\
        ";
    InitializeChecker(&argv, "_.ets", SRC, &checker, &program);

    auto *varbinder = program.VarBinder()->AsETSBinder();
    auto *const base_type = FindClassType(varbinder, "Base");
    ASSERT_NE(base_type, nullptr);
    auto *const derived1_type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived1");
    ASSERT_NE(derived1_type, nullptr);
    auto *const derived2_type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived2");
    ASSERT_NE(derived2_type, nullptr);

    // Test normalization: int | (int | string) | number ==> string | number
    auto *const ut1_type = FindTypeAlias(&checker, "UT1");
    ASSERT_NE(ut1_type, nullptr);
    ASSERT_TRUE(ut1_type->IsETSUnionType());
    auto *ut1 = ut1_type->AsETSUnionType();
    ASSERT_EQ(ut1->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(ut1->ConstituentTypes().at(IDX0), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(ut1->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Test normalization: int | UT | number ==> string | number
    auto *const ut2_type = FindTypeAlias(&checker, "UT2");
    ASSERT_NE(ut2_type, nullptr);
    ASSERT_TRUE(ut2_type->IsETSUnionType());
    auto *ut2 = ut2_type->AsETSUnionType();
    ASSERT_EQ(ut2->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(ut2->ConstituentTypes().at(IDX0), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(ut2->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Test normalization:
    // int | (Derived2 | Base) | Derived1 | (string | number | short) | (int | string) ==> Base | string | number
    auto *const ut3_type = FindTypeAlias(&checker, "UT3");
    ASSERT_NE(ut3_type, nullptr);
    ASSERT_TRUE(ut3_type->IsETSUnionType());
    auto *ut3 = ut3_type->AsETSUnionType();
    ASSERT_EQ(ut3->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX0), base_type);
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX1), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX2), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithNever)
{
    // Test normalization: int | never | number ==> number
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    ArenaVector<checker::Type *> union_constituents(checker.Allocator()->Adapter());
    union_constituents.emplace_back(checker.GlobalIntType());
    union_constituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalBuiltinNeverType());
    union_constituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Create union type, which will be normalized inside creation function
    auto *const normalized_type = checker.CreateETSUnionType(std::move(union_constituents));
    ASSERT_NE(normalized_type, nullptr);
    ASSERT_TRUE(normalized_type->IsETSObjectType());
    ASSERT_EQ(normalized_type, checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

}  // namespace panda::es2panda
