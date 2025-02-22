/*
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
#include <gtest/gtest.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include "assembly-program.h"
#include "test/unit/annotations/annotations_emit_test.h"

namespace ark::es2panda::compiler::test {

class AnnotationsforFunction : public AnnotationEmitTest {
public:
    AnnotationsforFunction() = default;

    ~AnnotationsforFunction() override = default;

    void RunAnnotationEmitTest(const std::string_view text)
    {
        auto program = GetCurrentProgram(text);
        ASSERT_NE(program, nullptr);

        CheckAnnotations(program.get());
        CheckFunctionAnnotations(program.get());
        CheckFunctionParameterAnnotations(program.get());
    }

    void CheckAnnotations(pandasm::Program *program)
    {
        const std::string annoName = "Anno";
        const std::vector<std::pair<std::string, std::string>> expectedAnnotations = {
            {{"a", "1.000000"}},
        };
        AnnotationEmitTest::CheckAnnoDecl(program, annoName, expectedAnnotations);
    }

    void CheckFunctionAnnotations(pandasm::Program *program)
    {
        const std::string funcName1 = "ETSGLOBAL.foo:std.core.Double;void;";
        const std::string funcName2 = "ETSGLOBAL.foo:void;";
        const AnnotationMap expectedFuncAnnotations = {
            {"Anno", {{"a", "1.000000"}}},
        };
        AnnotationEmitTest::CheckFunctionAnnotations(program, funcName1, true, expectedFuncAnnotations);
        AnnotationEmitTest::CheckFunctionAnnotations(program, funcName2, true, expectedFuncAnnotations);
    }

    void CheckFunctionParameterAnnotations(pandasm::Program *program)
    {
        const std::string funcName1 = "ETSGLOBAL.foo:std.core.Double;void;";
        const uint32_t paramIndex1 = 0;
        const AnnotationMap expectedFuncAnnotations1 = {
            {"Anno", {{"a", "1.000000"}}},
        };
        const std::string funcName2 = "A.bar:f64;f64[];void;";
        // Index 0 is the parameter 'this'
        const uint32_t paramIndex2 = 1;
        const uint32_t paramIndex3 = 2;
        const AnnotationMap expectedFuncAnnotations2 = {
            {"Anno",
             {
                 {"a", "2.000000"},
             }},
        };
        const AnnotationMap expectedFuncAnnotations3 = {
            {"Anno",
             {
                 {"a", "3.000000"},
             }},
        };
        AnnotationEmitTest::CheckFunctionParameterAnnotations(program, funcName1, true, paramIndex1,
                                                              expectedFuncAnnotations1);
        AnnotationEmitTest::CheckFunctionParameterAnnotations(program, funcName2, false, paramIndex2,
                                                              expectedFuncAnnotations2);
        AnnotationEmitTest::CheckFunctionParameterAnnotations(program, funcName2, false, paramIndex3,
                                                              expectedFuncAnnotations3);
    }

private:
    NO_COPY_SEMANTIC(AnnotationsforFunction);
    NO_MOVE_SEMANTIC(AnnotationsforFunction);
};

// #22952
TEST_F(AnnotationsforFunction, DISABLED_annotations_for_function)
{
    std::string_view text = R"(
    @interface Anno {
        a:number = 1
    }

    @Anno
    function foo(@Anno a ?: number) {}

    class A {
        bar(@Anno(2) a : number, @Anno(3) ...rest : number[]) {}
    })";

    RunAnnotationEmitTest(text);
}

}  // namespace ark::es2panda::compiler::test