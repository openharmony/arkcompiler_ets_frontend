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
#include "macros.h"

#include "assembler/assembly-program.h"
#include "ir/astDump.h"
#include "ir/expressions/literals/stringLiteral.h"

#include "bytecode_optimizer/bytecodeopt_options.h"
#include "compiler/compiler_logger.h"
#include "mem/arena_allocator.h"
#include "mem/pool_manager.h"
#include "es2panda.h"
#include "util/arktsconfig.h"
#include "util/generateBin.h"
#include "util/options.h"
#include "libpandabase/mem/mem.h"

class ASTDumperTest : public testing::Test {
public:
    ASTDumperTest()
    {
        constexpr auto COMPILER_SIZE = 268435456;

        panda::mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        panda::PoolManager::Initialize(panda::PoolType::MMAP);
    }
    ~ASTDumperTest() override
    {
        panda::PoolManager::Finalize();
        panda::mem::MemConfig::Finalize();
    };

    static panda::pandasm::Program *GetProgram(int argc, const char **argv, std::string_view fileName,
                                               std::string_view src)
    {
        auto options = std::make_unique<panda::es2panda::util::Options>();
        if (!options->Parse(argc, argv)) {
            std::cerr << options->ErrorMsg() << std::endl;
            return nullptr;
        }

        panda::Logger::ComponentMask mask {};
        mask.set(panda::Logger::Component::ES2PANDA);
        panda::Logger::InitializeStdLogging(panda::Logger::LevelFromString(options->LogLevel()), mask);

        panda::es2panda::Compiler compiler(options->Extension(), options->ThreadCount());
        panda::es2panda::SourceFile input(fileName, src, options->ParseModule());

        return compiler.Compile(input, options->CompilerOptions());
    }

    NO_COPY_SEMANTIC(ASTDumperTest);
    NO_MOVE_SEMANTIC(ASTDumperTest);

private:
};

TEST_F(ASTDumperTest, DumpJsonSimple)
{
    static constexpr std::string_view FILE_NAME = "dummy.ets";
    static constexpr std::string_view SRC =
        "\
        function main(args: String[]): int {\
            let a: int = 2;\
            let b: int = 3;\
            return a + b;\
        }";

    int argc = 1;
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";

    auto program = std::unique_ptr<panda::pandasm::Program> {GetProgram(argc, &argv, FILE_NAME, SRC)};

    ASSERT_NE(program, nullptr);

    auto dumpStr = program->JsonDump();

    ASSERT_FALSE(dumpStr.empty());
}

TEST_F(ASTDumperTest, DumpJsonUTF16Char)
{
    static constexpr std::string_view FILE_NAME = "dummy.ets";
    static constexpr std::string_view SRC =
        "\
        function main(args: String[]): int {\
            let a: char = c'\\uDBFF';\
            let b: char = c'\\uDC00';\
            console.log(a);\
            console.log(b);\
            return 0;\
        }";

    int argc = 1;
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    const char *argv = "../../../bin/es2panda";

    auto program = std::unique_ptr<panda::pandasm::Program> {GetProgram(argc, &argv, FILE_NAME, SRC)};

    ASSERT_NE(program, nullptr);

    auto dumpStr = program->JsonDump();

    ASSERT_FALSE(dumpStr.empty());
}

TEST_F(ASTDumperTest, DumpEtsSrcSimple)
{
    static constexpr std::string_view FILE_NAME = "dummy.ets";
    static constexpr std::string_view SRC =
        "\
        function main(args: String[]): int {\
            let a: int = 2;\
            let b: int = 3;\
            return a + b;\
        }";

    int argc = 1;
    const char *argv =
        "../../../bin/es2panda "
        "--extension=ets "
        "--dump-ets-src-before-phases=\"plugins-after-parse:lambda-lowering:checker:plugins-after-check:generate-ts-"
        "declarations:op-assignment:tuple-lowering:union-property-access:plugins-after-lowering\"";

    auto program = std::unique_ptr<panda::pandasm::Program> {GetProgram(argc, &argv, FILE_NAME, SRC)};

    ASSERT_NE(program, nullptr);

    auto dumpStr = program->JsonDump();

    ASSERT_FALSE(dumpStr.empty());
}
