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
        publicContext_ = std::make_unique<public_lib::Context>();
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

    void InitializeChecker(const char **argv, std::string_view fileName, std::string_view src,
                           checker::ETSChecker *checker, parser::Program *program)
    {
        InitializeChecker<parser::ETSParser, varbinder::ETSBinder, checker::ETSChecker, checker::ETSAnalyzer,
                          compiler::ETSCompiler, compiler::ETSGen, compiler::StaticRegSpiller,
                          compiler::ETSFunctionEmitter, compiler::ETSEmitter>(argv, fileName, src, checker, program);
    }

    template <typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter, typename AstCompiler>
    compiler::CompilerContext::CodeGenCb MakeCompileJob()
    {
        return [this](compiler::CompilerContext *context, varbinder::FunctionScope *scope,
                      compiler::ProgramElement *programElement) -> void {
            RegSpiller regSpiller;
            AstCompiler astcompiler;
            CodeGen cg(allocator_.get(), &regSpiller, context, scope, programElement, &astcompiler);
            FunctionEmitter funcEmitter(&cg, programElement);
            funcEmitter.Generate();
        };
    }

    template <typename Parser, typename VarBinder, typename Checker, typename Analyzer, typename AstCompiler,
              typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter>
    void InitializeChecker(const char **argv, std::string_view fileName, std::string_view src,
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
        SourceFile input(fileName, src, options->ParseModule());
        compiler::CompilationUnit unit {input, options->CompilerOptions(), 0, options->Extension()};
        auto getPhases = compiler::GetPhaseList(ScriptExtension::ETS);

        program->MarkEntry();
        auto parser = Parser(program, unit.options, static_cast<parser::ParserStatus>(unit.rawParserStatus));
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

        publicContext_->sourceFile = &unit.input;
        publicContext_->allocator = allocator_.get();
        publicContext_->parser = &parser;
        publicContext_->checker = context.Checker();
        publicContext_->analyzer = publicContext_->checker->GetAnalyzer();
        publicContext_->compilerContext = &context;
        publicContext_->emitter = context.GetEmitter();

        parser.ParseScript(unit.input, unit.options.compilationMode == CompilationMode::GEN_STD_LIB);
        if constexpr (std::is_same_v<Parser, parser::ETSParser> && std::is_same_v<VarBinder, varbinder::ETSBinder>) {
            reinterpret_cast<varbinder::ETSBinder *>(varbinder)->FillResolvedImportPathes(
                parser.ResolvedParsedSourcesMap(), allocator_.get());
        }
        for (auto *phase : getPhases) {
            if (!phase->Apply(publicContext_.get(), program)) {
                return;
            }
        }
    }

    static checker::Type *FindClassType(varbinder::ETSBinder *varbinder, std::string_view className)
    {
        auto classDefs = varbinder->AsETSBinder()->GetRecordTable()->ClassDefinitions();
        auto baseClass = std::find_if(classDefs.begin(), classDefs.end(), [className](ir::ClassDefinition *cdef) {
            return cdef->Ident()->Name().Is(className);
        });
        if (baseClass == classDefs.end()) {
            return nullptr;
        }
        return (*baseClass)->TsType();
    }

    static checker::Type *FindTypeAlias(checker::ETSChecker *checker, std::string_view aliasName)
    {
        auto *foundVar =
            checker->Scope()->FindLocal(aliasName, varbinder::ResolveBindingOptions::ALL)->AsLocalVariable();
        if (foundVar == nullptr) {
            return nullptr;
        }
        return foundVar->Declaration()->Node()->AsTSTypeAliasDeclaration()->TypeAnnotation()->TsType();
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
    std::unique_ptr<public_lib::Context> publicContext_;
};

TEST_F(UnionNormalizationTest, UnionWithObject)
{
    // Test normalization: int | Object | string ==> Object
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    ArenaVector<checker::Type *> unionConstituents(checker.Allocator()->Adapter());
    unionConstituents.emplace_back(checker.GlobalIntType());
    unionConstituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalETSObjectType());
    unionConstituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalETSStringBuiltinType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker.CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSObjectType());
    ASSERT_EQ(normalizedType, checker.GlobalETSObjectType());
}

TEST_F(UnionNormalizationTest, UnionWithIdenticalTypes1)
{
    // Test normalization: number | Base | string | number ==> number | Base | string
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "class Base {}", &checker, &program);

    auto *const baseType = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);

    ArenaVector<checker::Type *> unionConstituents(checker.Allocator()->Adapter());
    unionConstituents.emplace_back(checker.GlobalDoubleType());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker.GlobalBuiltinETSStringType());
    unionConstituents.emplace_back(checker.GlobalDoubleType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker.CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), baseType);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX2), checker.GlobalBuiltinETSStringType());
}

TEST_F(UnionNormalizationTest, UnionWithIdenticalTypes2)
{
    // Test normalization: Base | int | Base | double | short | number ==> Base | number
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "class Base {}", &checker, &program);

    auto *const baseType = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);

    ArenaVector<checker::Type *> unionConstituents(checker.Allocator()->Adapter());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker.GlobalIntType());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker.GlobalDoubleType());
    unionConstituents.emplace_back(checker.GlobalShortType());
    unionConstituents.emplace_back(checker.GlobalDoubleType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker.CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), baseType);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithNumeric1)
{
    // Test normalization: boolean | int | double | short ==> boolean | double
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    ArenaVector<checker::Type *> unionConstituents(checker.Allocator()->Adapter());
    unionConstituents.emplace_back(checker.GlobalETSBooleanType());
    unionConstituents.emplace_back(checker.GlobalIntType());
    unionConstituents.emplace_back(checker.GlobalDoubleType());
    unionConstituents.emplace_back(checker.GlobalShortType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker.CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker.GetGlobalTypesHolder()->GlobalETSBooleanBuiltinType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithNumeric2)
{
    // Test normalization: string | int | Base | double | short ==> string | Base | double
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "class Base {}", &checker, &program);

    auto *const baseType = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);

    ArenaVector<checker::Type *> unionConstituents(checker.Allocator()->Adapter());
    unionConstituents.emplace_back(checker.GlobalBuiltinETSStringType());
    unionConstituents.emplace_back(checker.GlobalIntType());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker.GlobalDoubleType());
    unionConstituents.emplace_back(checker.GlobalShortType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker.CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), baseType);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX2), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
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

    auto *const baseType = FindClassType(program.VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);
    auto *const derived1Type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived1");
    ASSERT_NE(derived1Type, nullptr);
    auto *const derived2Type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived2");
    ASSERT_NE(derived2Type, nullptr);

    // Test normalization: Derived1 | Base ==> Base
    ArenaVector<checker::Type *> unionConstituents1(checker.Allocator()->Adapter());
    unionConstituents1.emplace_back(derived1Type);
    unionConstituents1.emplace_back(baseType);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType1 = checker.CreateETSUnionType(std::move(unionConstituents1));
    ASSERT_NE(normalizedType1, nullptr);
    ASSERT_TRUE(normalizedType1->IsETSObjectType());
    ASSERT_EQ(normalizedType1, baseType);

    // Test normalization: Base | Derived2 ==> Base
    ArenaVector<checker::Type *> unionConstituents2(checker.Allocator()->Adapter());
    unionConstituents2.emplace_back(baseType);
    unionConstituents2.emplace_back(derived2Type);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType2 = checker.CreateETSUnionType(std::move(unionConstituents2));
    ASSERT_NE(normalizedType2, nullptr);
    ASSERT_TRUE(normalizedType2->IsETSObjectType());
    ASSERT_EQ(normalizedType2, baseType);

    // Test normalization: Derived1 | Derived2 ==> Derived1 | Derived2
    ArenaVector<checker::Type *> unionConstituents3(checker.Allocator()->Adapter());
    unionConstituents3.emplace_back(derived1Type);
    unionConstituents3.emplace_back(derived2Type);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType3 = checker.CreateETSUnionType(std::move(unionConstituents3));
    ASSERT_NE(normalizedType3, nullptr);
    auto *const unionType = normalizedType3->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), derived1Type);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), derived2Type);

    // Test normalization: Derived2 | Base | Derived1 ==> Base
    ArenaVector<checker::Type *> unionConstituents4(checker.Allocator()->Adapter());
    unionConstituents4.emplace_back(derived1Type);
    unionConstituents4.emplace_back(baseType);
    unionConstituents4.emplace_back(derived2Type);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType4 = checker.CreateETSUnionType(std::move(unionConstituents4));
    ASSERT_NE(normalizedType4, nullptr);
    ASSERT_TRUE(normalizedType4->IsETSObjectType());
    ASSERT_EQ(normalizedType4, baseType);
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
    auto *const baseType = FindClassType(varbinder, "Base");
    ASSERT_NE(baseType, nullptr);
    auto *const derived1Type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived1");
    ASSERT_NE(derived1Type, nullptr);
    auto *const derived2Type = FindClassType(program.VarBinder()->AsETSBinder(), "Derived2");
    ASSERT_NE(derived2Type, nullptr);

    // Test normalization: int | (int | string) | number ==> string | number
    auto *const ut1Type = FindTypeAlias(&checker, "UT1");
    ASSERT_NE(ut1Type, nullptr);
    ASSERT_TRUE(ut1Type->IsETSUnionType());
    auto *ut1 = ut1Type->AsETSUnionType();
    ASSERT_EQ(ut1->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(ut1->ConstituentTypes().at(IDX0), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(ut1->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Test normalization: int | UT | number ==> string | number
    auto *const ut2Type = FindTypeAlias(&checker, "UT2");
    ASSERT_NE(ut2Type, nullptr);
    ASSERT_TRUE(ut2Type->IsETSUnionType());
    auto *ut2 = ut2Type->AsETSUnionType();
    ASSERT_EQ(ut2->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(ut2->ConstituentTypes().at(IDX0), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(ut2->ConstituentTypes().at(IDX1), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Test normalization:
    // int | (Derived2 | Base) | Derived1 | (string | number | short) | (int | string) ==> Base | string | number
    auto *const ut3Type = FindTypeAlias(&checker, "UT3");
    ASSERT_NE(ut3Type, nullptr);
    ASSERT_TRUE(ut3Type->IsETSUnionType());
    auto *ut3 = ut3Type->AsETSUnionType();
    ASSERT_EQ(ut3->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX0), baseType);
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX1), checker.GlobalBuiltinETSStringType());
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX2), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionStringLiterals)
{
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    // Test normalization: string | "abc" ==> string
    ArenaVector<checker::Type *> unionConstituents1(checker.Allocator()->Adapter());
    unionConstituents1.emplace_back(checker.GlobalBuiltinETSStringType());
    unionConstituents1.emplace_back(checker.CreateETSStringLiteralType("abc"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType1 = checker.CreateETSUnionType(std::move(unionConstituents1));
    ASSERT_NE(normalizedType1, nullptr);
    ASSERT_TRUE(normalizedType1->IsETSObjectType());
    ASSERT_EQ(normalizedType1, checker.GlobalBuiltinETSStringType());

    // Test normalization: "abc" | string | string ==> string
    ArenaVector<checker::Type *> unionConstituents2(checker.Allocator()->Adapter());
    unionConstituents2.emplace_back(checker.CreateETSStringLiteralType("abc"));
    unionConstituents2.emplace_back(checker.GlobalBuiltinETSStringType());
    unionConstituents2.emplace_back(checker.GlobalBuiltinETSStringType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType2 = checker.CreateETSUnionType(std::move(unionConstituents2));
    ASSERT_NE(normalizedType2, nullptr);
    ASSERT_TRUE(normalizedType2->IsETSObjectType());
    ASSERT_EQ(normalizedType2, checker.GlobalBuiltinETSStringType());

    // Test normalization: number | "abc" | string | "xy" ==> number | string
    ArenaVector<checker::Type *> unionConstituents3(checker.Allocator()->Adapter());
    unionConstituents3.emplace_back(checker.GlobalDoubleType());
    unionConstituents3.emplace_back(checker.CreateETSStringLiteralType("abc"));
    unionConstituents3.emplace_back(checker.GlobalBuiltinETSStringType());
    unionConstituents3.emplace_back(checker.CreateETSStringLiteralType("xy"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType3 = checker.CreateETSUnionType(std::move(unionConstituents3));
    ASSERT_NE(normalizedType3, nullptr);
    ASSERT_TRUE(normalizedType3->IsETSUnionType());
    auto *const unionType = normalizedType3->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), checker.GlobalBuiltinETSStringType());
}

TEST_F(UnionNormalizationTest, UnionWithNever)
{
    // Test normalization: int | never | number ==> number
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";
    checker::ETSChecker checker;
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    InitializeChecker(&argv, "_.ets", "", &checker, &program);

    ArenaVector<checker::Type *> unionConstituents(checker.Allocator()->Adapter());
    unionConstituents.emplace_back(checker.GlobalIntType());
    unionConstituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalBuiltinNeverType());
    unionConstituents.emplace_back(checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker.CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSObjectType());
    ASSERT_EQ(normalizedType, checker.GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

}  // namespace panda::es2panda
