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
#include "test/utils/panda_executable_path_getter.h"

namespace {

class TestParams {
public:
    TestParams(std::string_view src, std::initializer_list<const char *> argsList) : src_ {src}
    {
        argsList_.push_back(test::utils::PandaExecutablePathGetter::Get()[0]);
        argsList_.insert(argsList_.end(), argsList.begin(), argsList.end());
    }
    auto GetSrc()
    {
        return src_;
    };
    auto GetExec()
    {
        return argsList_[0];
    };
    auto GetFilename()
    {
        return "dummy.sts";
    };
    auto GetArgs() const
    {
        return ark::Span {argsList_};
    };

private:
    std::string_view src_;
    std::vector<const char *> argsList_;
};

TestParams DumpJsonSimple()
{
    static constexpr std::string_view SRC =
        "\
        function main(args: String[]): int {\
            let a: int = 2;\
            let b: int = 3;\
            return a + b;\
        }";

    return TestParams {SRC, {}};
}

TestParams DumpJsonUTF16Char()
{
    static constexpr std::string_view SRC =
        "\
        function main(args: String[]): int {\
            let a: char = c'\\uDBFF';\
            let b: char = c'\\uDC00';\
            console.log(a);\
            console.log(b);\
            return 0;\
        }";

    return TestParams {SRC, {}};
}

TestParams DumpEtsSrcSimple()
{
    static constexpr std::string_view SRC =
        "\
        function main(args: String[]): int {\
            let a: int = 2;\
            let b: int = 3;\
            return a + b;\
        }";

    return TestParams {SRC,
                       {"--extension=sts",
                        "--dump-ets-src-before-phases=plugins-after-parse,plugins-after-check,plugins-after-lowering"}};
}

}  // namespace

class ASTDumperTest : public testing::TestWithParam<TestParams> {
public:
    ASTDumperTest()
    {
        constexpr auto COMPILER_SIZE = 268435456;

        ark::mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        ark::PoolManager::Initialize(ark::PoolType::MMAP);
    }

    ~ASTDumperTest() override
    {
        ark::PoolManager::Finalize();
        ark::mem::MemConfig::Finalize();
    };

    static ark::pandasm::Program *GetProgram(TestParams params)
    {
        auto options = std::make_unique<ark::es2panda::util::Options>(params.GetExec());
        if (!options->Parse(params.GetArgs())) {
            std::cerr << options->ErrorMsg() << std::endl;
            return nullptr;
        }

        ark::Logger::ComponentMask mask {};
        mask.set(ark::Logger::Component::ES2PANDA);
        ark::Logger::InitializeStdLogging(options->LogLevel(), mask);

        ark::es2panda::Compiler compiler(options->GetExtension(), options->GetThread());
        ark::es2panda::SourceFile input(params.GetFilename(), params.GetSrc(), options->IsModule());

        return compiler.Compile(input, *options);
    }

    NO_COPY_SEMANTIC(ASTDumperTest);
    NO_MOVE_SEMANTIC(ASTDumperTest);
};

TEST_P(ASTDumperTest, CheckJsonDump)
{
    auto program = std::unique_ptr<ark::pandasm::Program> {GetProgram(GetParam())};
    ASSERT(program);

    auto dumpStr = program->JsonDump();
    ASSERT(!dumpStr.empty());
}

INSTANTIATE_TEST_SUITE_P(ASTDumperTestParamList, ASTDumperTest,
                         ::testing::Values(DumpJsonSimple(), DumpJsonUTF16Char()));

TEST_F(ASTDumperTest, CheckSrcDump)
{
    std::stringstream dumpStr;
    std::streambuf *prevcoutbuf = std::cout.rdbuf(dumpStr.rdbuf());

    auto program = std::unique_ptr<ark::pandasm::Program> {GetProgram(DumpEtsSrcSimple())};

    std::cout.rdbuf(prevcoutbuf);

    ASSERT(program);
    ASSERT(!dumpStr.str().empty());
}
