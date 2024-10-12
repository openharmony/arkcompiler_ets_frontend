/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "test/utils/panda_executable_path_getter.h"
#include "checker/types/globalTypesHolder.h"

namespace ark::es2panda {

class UnionNormalizationTest : public testing::Test {
public:
    UnionNormalizationTest()
        : allocator_(std::make_unique<ArenaAllocator>(SpaceType::SPACE_TYPE_COMPILER)),
          publicContext_ {std::make_unique<public_lib::Context>()},
          program_ {parser::Program::NewProgram<varbinder::ETSBinder>(Allocator())},
          es2pandaPath_ {test::utils::PandaExecutablePathGetter {}.Get()}
    {
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

    parser::Program *Program()
    {
        return &program_;
    }

    checker::ETSChecker *Checker()
    {
        return &checker_;
    }

    void InitializeChecker(std::string_view fileName, std::string_view src)
    {
        auto es2pandaPathPtr = es2pandaPath_.c_str();
        ASSERT(es2pandaPathPtr);

        InitializeChecker<parser::ETSParser, varbinder::ETSBinder, checker::ETSChecker, checker::ETSAnalyzer,
                          compiler::ETSCompiler, compiler::ETSGen, compiler::StaticRegSpiller,
                          compiler::ETSFunctionEmitter, compiler::ETSEmitter>(&es2pandaPathPtr, fileName, src,
                                                                              &checker_, &program_);
    }

    template <typename CodeGen, typename RegSpiller, typename FunctionEmitter, typename Emitter, typename AstCompiler>
    public_lib::Context::CodeGenCb MakeCompileJob()
    {
        return [this](public_lib::Context *context, varbinder::FunctionScope *scope,
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
        auto options = std::make_unique<ark::es2panda::util::Options>();
        if (!options->Parse(1, argv)) {
            std::cerr << options->ErrorMsg() << std::endl;
            return;
        }

        ark::Logger::ComponentMask mask {};
        mask.set(ark::Logger::Component::ES2PANDA);
        ark::Logger::InitializeStdLogging(ark::Logger::LevelFromString(options->LogLevel()), mask);

        Compiler compiler(options->Extension(), options->ThreadCount());
        SourceFile input(fileName, src, options->ParseModule());
        compiler::CompilationUnit unit {input, *options, 0, options->Extension()};
        auto getPhases = compiler::GetPhaseList(ScriptExtension::ETS);

        program->MarkEntry();
        auto parser =
            Parser(program, unit.options.CompilerOptions(), static_cast<parser::ParserStatus>(unit.rawParserStatus));
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

        parser.ParseScript(unit.input, unit.options.CompilerOptions().compilationMode == CompilationMode::GEN_STD_LIB);
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
            checker->Scope()->FindLocal(aliasName, varbinder::ResolveBindingOptions::TYPE_ALIASES)->AsLocalVariable();
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
    parser::Program program_;
    std::string es2pandaPath_;
    checker::ETSChecker checker_;
};

TEST_F(UnionNormalizationTest, UnionWithObject)
{
    // Test normalization: int | Object | string ==> Object
    InitializeChecker("_.sts", "");

    auto checker = Checker();
    ASSERT(checker);

    ArenaVector<checker::Type *> unionConstituents(checker->Allocator()->Adapter());
    unionConstituents.emplace_back(checker->GlobalIntType());
    unionConstituents.emplace_back(checker->GetGlobalTypesHolder()->GlobalETSObjectType());
    unionConstituents.emplace_back(checker->GetGlobalTypesHolder()->GlobalETSStringBuiltinType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker->CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSObjectType());
    ASSERT_EQ(normalizedType, checker->GlobalETSObjectType());
}

TEST_F(UnionNormalizationTest, UnionWithIdenticalTypes1)
{
    // Test normalization: number | Base | string | number ==> number | Base | string
    InitializeChecker("_.sts", "class Base {}");

    auto program = Program();
    ASSERT(program);

    auto *const baseType = FindClassType(program->VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);

    auto checker = Checker();
    ASSERT(checker);

    ArenaVector<checker::Type *> unionConstituents(checker->Allocator()->Adapter());
    unionConstituents.emplace_back(checker->GlobalDoubleType());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker->GlobalBuiltinETSStringType());
    unionConstituents.emplace_back(checker->GlobalDoubleType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker->CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), baseType);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX2), checker->GlobalBuiltinETSStringType());
}

TEST_F(UnionNormalizationTest, DISABLED_UnionWithIdenticalTypes2)
{
    // Test normalization: Base | int | Base | double | short | number ==> Base | number
    InitializeChecker("_.sts", "class Base {}");

    auto program = Program();
    ASSERT(program);

    auto *const baseType = FindClassType(program->VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);

    auto checker = Checker();
    ASSERT(checker);

    ArenaVector<checker::Type *> unionConstituents(checker->Allocator()->Adapter());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker->GlobalIntType());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker->GlobalDoubleType());
    unionConstituents.emplace_back(checker->GlobalShortType());
    unionConstituents.emplace_back(checker->GlobalDoubleType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker->CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), baseType);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, DISABLED_UnionWithNumeric1)
{
    // Test normalization: boolean | int | double | short ==> boolean | double
    InitializeChecker("_.sts", "");

    auto checker = Checker();
    ASSERT(checker);

    ArenaVector<checker::Type *> unionConstituents(checker->Allocator()->Adapter());
    unionConstituents.emplace_back(checker->GlobalETSBooleanType());
    unionConstituents.emplace_back(checker->GlobalIntType());
    unionConstituents.emplace_back(checker->GlobalDoubleType());
    unionConstituents.emplace_back(checker->GlobalShortType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker->CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker->GetGlobalTypesHolder()->GlobalETSBooleanBuiltinType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, DISABLED_UnionWithNumeric2)
{
    // Test normalization: string | int | Base | double | short ==> string | Base | double
    InitializeChecker("_.sts", "class Base {}");

    auto program = Program();
    ASSERT(program);

    auto *const baseType = FindClassType(program->VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);

    auto checker = Checker();
    ASSERT(checker);

    ArenaVector<checker::Type *> unionConstituents(checker->Allocator()->Adapter());
    unionConstituents.emplace_back(checker->GlobalBuiltinETSStringType());
    unionConstituents.emplace_back(checker->GlobalIntType());
    unionConstituents.emplace_back(baseType);
    unionConstituents.emplace_back(checker->GlobalDoubleType());
    unionConstituents.emplace_back(checker->GlobalShortType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker->CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSUnionType());
    auto *const unionType = normalizedType->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker->GlobalBuiltinETSStringType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), baseType);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX2), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionWithSubTypes)
{
    // Test 4 cases of normalization
    static constexpr std::string_view SRC =
        "\
        class Base {}\
        class Derived1 extends Base {}\
        class Derived2 extends Base {}\
        ";
    InitializeChecker("_.sts", SRC);

    auto program = Program();
    ASSERT(program);

    auto *const baseType = FindClassType(program->VarBinder()->AsETSBinder(), "Base");
    ASSERT_NE(baseType, nullptr);
    auto *const derived1Type = FindClassType(program->VarBinder()->AsETSBinder(), "Derived1");
    ASSERT_NE(derived1Type, nullptr);
    auto *const derived2Type = FindClassType(program->VarBinder()->AsETSBinder(), "Derived2");
    ASSERT_NE(derived2Type, nullptr);

    auto checker = Checker();
    ASSERT(checker);

    // Test normalization: Derived1 | Base ==> Base
    ArenaVector<checker::Type *> unionConstituents1(checker->Allocator()->Adapter());
    unionConstituents1.emplace_back(derived1Type);
    unionConstituents1.emplace_back(baseType);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType1 = checker->CreateETSUnionType(std::move(unionConstituents1));
    ASSERT_NE(normalizedType1, nullptr);
    ASSERT_TRUE(normalizedType1->IsETSObjectType());
    ASSERT_EQ(normalizedType1, baseType);

    // Test normalization: Base | Derived2 ==> Base
    ArenaVector<checker::Type *> unionConstituents2(checker->Allocator()->Adapter());
    unionConstituents2.emplace_back(baseType);
    unionConstituents2.emplace_back(derived2Type);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType2 = checker->CreateETSUnionType(std::move(unionConstituents2));
    ASSERT_NE(normalizedType2, nullptr);
    ASSERT_TRUE(normalizedType2->IsETSObjectType());
    ASSERT_EQ(normalizedType2, baseType);

    // Test normalization: Derived1 | Derived2 ==> Derived1 | Derived2
    ArenaVector<checker::Type *> unionConstituents3(checker->Allocator()->Adapter());
    unionConstituents3.emplace_back(derived1Type);
    unionConstituents3.emplace_back(derived2Type);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType3 = checker->CreateETSUnionType(std::move(unionConstituents3));
    ASSERT_NE(normalizedType3, nullptr);
    auto *const unionType = normalizedType3->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), derived1Type);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), derived2Type);

    // Test normalization: Derived2 | Base | Derived1 ==> Base
    ArenaVector<checker::Type *> unionConstituents4(checker->Allocator()->Adapter());
    unionConstituents4.emplace_back(derived1Type);
    unionConstituents4.emplace_back(baseType);
    unionConstituents4.emplace_back(derived2Type);

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType4 = checker->CreateETSUnionType(std::move(unionConstituents4));
    ASSERT_NE(normalizedType4, nullptr);
    ASSERT_TRUE(normalizedType4->IsETSObjectType());
    ASSERT_EQ(normalizedType4, baseType);
}

TEST_F(UnionNormalizationTest, DISABLED_UnionLinearization)
{
    // Test 3 cases of normalization
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
    InitializeChecker("_.sts", SRC);

    auto program = Program();
    ASSERT(program);

    auto *varbinder = program->VarBinder()->AsETSBinder();
    auto *const baseType = FindClassType(varbinder, "Base");
    ASSERT_NE(baseType, nullptr);
    auto *const derived1Type = FindClassType(program->VarBinder()->AsETSBinder(), "Derived1");
    ASSERT_NE(derived1Type, nullptr);
    auto *const derived2Type = FindClassType(program->VarBinder()->AsETSBinder(), "Derived2");
    ASSERT_NE(derived2Type, nullptr);

    auto checker = Checker();
    ASSERT(checker);

    // Test normalization: int | (int | string) | number ==> string | number
    auto *const ut1Type = FindTypeAlias(checker, "UT1");
    ASSERT_NE(ut1Type, nullptr);
    ASSERT_TRUE(ut1Type->IsETSUnionType());
    auto *ut1 = ut1Type->AsETSUnionType();
    ASSERT_EQ(ut1->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(ut1->ConstituentTypes().at(IDX0), checker->GlobalBuiltinETSStringType());
    ASSERT_EQ(ut1->ConstituentTypes().at(IDX1), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Test normalization: int | UT | number ==> string | number
    auto *const ut2Type = FindTypeAlias(checker, "UT2");
    ASSERT_NE(ut2Type, nullptr);
    ASSERT_TRUE(ut2Type->IsETSUnionType());
    auto *ut2 = ut2Type->AsETSUnionType();
    ASSERT_EQ(ut2->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(ut2->ConstituentTypes().at(IDX0), checker->GlobalBuiltinETSStringType());
    ASSERT_EQ(ut2->ConstituentTypes().at(IDX1), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Test normalization:
    // int | (Derived2 | Base) | Derived1 | (string | number | short) | (int | string) ==> Base | string | number
    auto *const ut3Type = FindTypeAlias(checker, "UT3");
    ASSERT_NE(ut3Type, nullptr);
    ASSERT_TRUE(ut3Type->IsETSUnionType());
    auto *ut3 = ut3Type->AsETSUnionType();
    ASSERT_EQ(ut3->ConstituentTypes().size(), SIZE3);
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX0), baseType);
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX1), checker->GlobalBuiltinETSStringType());
    ASSERT_EQ(ut3->ConstituentTypes().at(IDX2), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

TEST_F(UnionNormalizationTest, UnionStringLiterals1)
{
    InitializeChecker("_.sts", "");

    auto checker = Checker();
    ASSERT(checker);

    // Test normalization: string | "abc" ==> string
    ArenaVector<checker::Type *> unionConstituents1(checker->Allocator()->Adapter());
    unionConstituents1.emplace_back(checker->GlobalBuiltinETSStringType());
    unionConstituents1.emplace_back(checker->CreateETSStringLiteralType("abc"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType1 = checker->CreateETSUnionType(std::move(unionConstituents1));
    ASSERT_NE(normalizedType1, nullptr);
    ASSERT_TRUE(normalizedType1->IsETSObjectType());
    ASSERT_EQ(normalizedType1, checker->GlobalBuiltinETSStringType());

    // Test normalization: "abc" | string | string ==> string
    ArenaVector<checker::Type *> unionConstituents2(checker->Allocator()->Adapter());
    unionConstituents2.emplace_back(checker->CreateETSStringLiteralType("abc"));
    unionConstituents2.emplace_back(checker->GlobalBuiltinETSStringType());
    unionConstituents2.emplace_back(checker->GlobalBuiltinETSStringType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType2 = checker->CreateETSUnionType(std::move(unionConstituents2));
    ASSERT_NE(normalizedType2, nullptr);
    ASSERT_TRUE(normalizedType2->IsETSObjectType());
    ASSERT_EQ(normalizedType2, checker->GlobalBuiltinETSStringType());

    // Test normalization: number | "abc" | string | "xy" ==> number | string
    ArenaVector<checker::Type *> unionConstituents3(checker->Allocator()->Adapter());
    unionConstituents3.emplace_back(checker->GlobalDoubleType());
    unionConstituents3.emplace_back(checker->CreateETSStringLiteralType("abc"));
    unionConstituents3.emplace_back(checker->GlobalBuiltinETSStringType());
    unionConstituents3.emplace_back(checker->CreateETSStringLiteralType("xy"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType3 = checker->CreateETSUnionType(std::move(unionConstituents3));
    ASSERT_NE(normalizedType3, nullptr);
    ASSERT_TRUE(normalizedType3->IsETSUnionType());
    auto *const unionType = normalizedType3->AsETSUnionType();
    ASSERT_EQ(unionType->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX0), checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
    ASSERT_EQ(unionType->ConstituentTypes().at(IDX1), checker->GlobalBuiltinETSStringType());

    // Test normalization: "abcd" | "abcd" | "abcd" ==> "abcd"
    ArenaVector<checker::Type *> unionConstituents4(checker->Allocator()->Adapter());
    unionConstituents4.emplace_back(checker->CreateETSStringLiteralType("abcd"));
    unionConstituents4.emplace_back(checker->CreateETSStringLiteralType("abcd"));
    unionConstituents4.emplace_back(checker->CreateETSStringLiteralType("abcd"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType4 = checker->CreateETSUnionType(std::move(unionConstituents4));
    ASSERT_NE(normalizedType4, nullptr);
    ASSERT_TRUE(normalizedType4->IsETSStringType());
    ASSERT_EQ(normalizedType4->AsETSStringType()->GetValue(), "abcd");
}

TEST_F(UnionNormalizationTest, UnionStringLiterals2)
{
    InitializeChecker("_.sts", "");

    auto checker = Checker();
    ASSERT(checker);

    // Test absence of normalization: "ab1" | "bc2" | "cd3" ==> "ab1" | "bc2" | "cd3"
    ArenaVector<checker::Type *> unionConstituents1(checker->Allocator()->Adapter());
    unionConstituents1.emplace_back(checker->CreateETSStringLiteralType("ab1"));
    unionConstituents1.emplace_back(checker->CreateETSStringLiteralType("bc2"));
    unionConstituents1.emplace_back(checker->CreateETSStringLiteralType("cd3"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType1 = checker->CreateETSUnionType(std::move(unionConstituents1));
    ASSERT_NE(normalizedType1, nullptr);
    ASSERT_TRUE(normalizedType1->IsETSUnionType());
    auto *const unionType1 = normalizedType1->AsETSUnionType();
    ASSERT_EQ(unionType1->ConstituentTypes().size(), SIZE3);
    ASSERT_TRUE(unionType1->ConstituentTypes().at(IDX0)->IsETSStringType());
    ASSERT_EQ(unionType1->ConstituentTypes().at(IDX0)->AsETSStringType()->GetValue(), "ab1");
    ASSERT_TRUE(unionType1->ConstituentTypes().at(IDX1)->IsETSStringType());
    ASSERT_EQ(unionType1->ConstituentTypes().at(IDX1)->AsETSStringType()->GetValue(), "bc2");
    ASSERT_TRUE(unionType1->ConstituentTypes().at(IDX2)->IsETSStringType());
    ASSERT_EQ(unionType1->ConstituentTypes().at(IDX2)->AsETSStringType()->GetValue(), "cd3");

    // Test normalization: "ab1" | "bc2" | "ab1" ==> "ab1" | "bc2"
    ArenaVector<checker::Type *> unionConstituents2(checker->Allocator()->Adapter());
    unionConstituents2.emplace_back(checker->CreateETSStringLiteralType("ab1"));
    unionConstituents2.emplace_back(checker->CreateETSStringLiteralType("bc2"));
    unionConstituents2.emplace_back(checker->CreateETSStringLiteralType("ab1"));

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType2 = checker->CreateETSUnionType(std::move(unionConstituents2));
    ASSERT_NE(normalizedType2, nullptr);
    ASSERT_TRUE(normalizedType2->IsETSUnionType());
    auto *const unionType2 = normalizedType2->AsETSUnionType();
    ASSERT_EQ(unionType2->ConstituentTypes().size(), SIZE2);
    ASSERT_TRUE(unionType2->ConstituentTypes().at(IDX0)->IsETSStringType());
    ASSERT_EQ(unionType2->ConstituentTypes().at(IDX0)->AsETSStringType()->GetValue(), "ab1");
    ASSERT_TRUE(unionType2->ConstituentTypes().at(IDX1)->IsETSStringType());
    ASSERT_EQ(unionType2->ConstituentTypes().at(IDX1)->AsETSStringType()->GetValue(), "bc2");

    // Test absence of normalization: "ab1" | "bc2" | "cd3" | string | int ==> string | int
    ArenaVector<checker::Type *> unionConstituents3(checker->Allocator()->Adapter());
    unionConstituents3.emplace_back(checker->CreateETSStringLiteralType("ab1"));
    unionConstituents3.emplace_back(checker->CreateETSStringLiteralType("bc2"));
    unionConstituents3.emplace_back(checker->CreateETSStringLiteralType("cd3"));
    unionConstituents3.emplace_back(checker->GlobalBuiltinETSStringType());
    unionConstituents3.emplace_back(checker->GlobalIntType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType3 = checker->CreateETSUnionType(std::move(unionConstituents3));
    ASSERT_NE(normalizedType3, nullptr);
    ASSERT_TRUE(normalizedType3->IsETSUnionType());
    auto *const unionType3 = normalizedType3->AsETSUnionType();
    ASSERT_EQ(unionType3->ConstituentTypes().size(), SIZE2);
    ASSERT_EQ(unionType3->ConstituentTypes().at(IDX0), checker->GlobalBuiltinETSStringType());
    ASSERT_EQ(unionType3->ConstituentTypes().at(IDX1), checker->GetGlobalTypesHolder()->GlobalIntegerBuiltinType());
}

TEST_F(UnionNormalizationTest, DISABLED_UnionWithNever)
{
    // Test normalization: int | never | number ==> number
    InitializeChecker("_.sts", "");

    auto checker = Checker();
    ASSERT(checker);

    ArenaVector<checker::Type *> unionConstituents(checker->Allocator()->Adapter());
    unionConstituents.emplace_back(checker->GlobalIntType());
    unionConstituents.emplace_back(checker->GetGlobalTypesHolder()->GlobalBuiltinNeverType());
    unionConstituents.emplace_back(checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());

    // Create union type, which will be normalized inside creation function
    auto *const normalizedType = checker->CreateETSUnionType(std::move(unionConstituents));
    ASSERT_NE(normalizedType, nullptr);
    ASSERT_TRUE(normalizedType->IsETSObjectType());
    ASSERT_EQ(normalizedType, checker->GetGlobalTypesHolder()->GlobalDoubleBuiltinType());
}

}  // namespace ark::es2panda
