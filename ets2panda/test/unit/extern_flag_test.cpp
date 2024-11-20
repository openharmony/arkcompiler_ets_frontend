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

#include <gtest/gtest.h>

#include "assembler/assembly-program.h"
#include "es2panda.h"
#include "generated/signatures.h"
#include "libpandabase/mem/mem.h"
#include "macros.h"
#include "mem/pool_manager.h"
#include "util/options.h"
#include "test/utils/asm_test.h"

namespace ark::es2panda::compiler::test {

class DeclareTest : public ::test::utils::AsmTest {
public:
    DeclareTest() = default;
    ~DeclareTest() override = default;

    void CheckExternalFlag(std::string_view functionName)
    {
        pandasm::Function *fn = GetFunction(functionName, program_);
        ASSERT_TRUE(fn != nullptr) << "Function '" << functionName << "' not found";
        ASSERT_TRUE(HasExternalFlag(fn)) << "Function '" << fn->name << "' doesn't have External flag";
    }

    void CheckNoExternalFlag(std::string_view functionName)
    {
        pandasm::Function *fn = GetFunction(functionName, program_);
        ASSERT_TRUE(fn != nullptr) << "Function '" << functionName << "' not found";
        ASSERT_FALSE(HasExternalFlag(fn)) << "Function '" << fn->name << "' has External flag";
    }

private:
    bool HasExternalFlag(pandasm::Function *fn)
    {
        return (fn->metadata->GetAttribute("external"));
    }

    NO_COPY_SEMANTIC(DeclareTest);
    NO_MOVE_SEMANTIC(DeclareTest);
};

// === Function ===
TEST_F(DeclareTest, function_without_overloads_0)
{
    SetCurrentProgram(R"(
        declare function foo(tmp: double): string
    )");
    CheckExternalFlag("ETSGLOBAL.foo:f64;std.core.String;");
}

TEST_F(DeclareTest, function_with_overloads_0)
{
    SetCurrentProgram(R"(
        declare function foo(tmp?: double): string
    )");
    CheckExternalFlag("ETSGLOBAL.foo:std.core.Object;std.core.String;");
    CheckExternalFlag("ETSGLOBAL.foo:std.core.String;");
}

// === Method of class ===
TEST_F(DeclareTest, noImplclass_def_with_overload_0)
{
    SetCurrentProgram(R"(
        declare class my_class {
            public foo(arg?: int): string
        }
    )");
    CheckExternalFlag("my_class.foo:std.core.Object;std.core.String;");
    CheckExternalFlag("my_class.foo:std.core.String;");
}

// === Constructor of class ===
TEST_F(DeclareTest, class_constructor_without_parameters_0)
{
    SetCurrentProgram(R"(
        declare class A_class {
            static x: double
        }
    )");
    CheckExternalFlag("A_class.<ctor>:void;");
}

TEST_F(DeclareTest, class_constructor_without_parameters_1)
{
    SetCurrentProgram(R"(
        declare class A {
            constructor();
        }
    )");
    CheckExternalFlag("A.<ctor>:void;");
}

TEST_F(DeclareTest, class_implicit_constructor_0)
{
    SetCurrentProgram(R"(
        declare class A {
        }
    )");
    CheckExternalFlag("A.<ctor>:void;");
}

// === Method of interface ===
TEST_F(DeclareTest, noImplinterface_def_with_overload_0)
{
    SetCurrentProgram(R"(
        declare interface my_inter {
            foo(arg?: int): void
        }
    )");
    CheckExternalFlag("my_inter.foo:std.core.Object;void;");
    CheckExternalFlag("my_inter.foo:void;");
}

}  // namespace ark::es2panda::compiler::test
