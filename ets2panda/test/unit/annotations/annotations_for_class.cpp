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
#include <string>
#include <utility>
#include <vector>
#include "assembly-program.h"
#include "test/unit/annotations/annotations_emit_test.h"

namespace ark::es2panda::compiler::test {

class AnnotationsforClass : public AnnotationEmitTest {
public:
    AnnotationsforClass() = default;

    ~AnnotationsforClass() override = default;

    void RunAnnotationEmitTest(const std::string_view text)
    {
        auto program = GetCurrentProgram(text);
        ASSERT_NE(program, nullptr);

        CheckAnnotations(program.get());
        CheckClassAnnotations(program.get());
        CheckFunctionAnnotations(program.get());
    }

    void CheckAnnotations(pandasm::Program *program)
    {
        const std::string annoName = "Anno";
        const std::vector<std::pair<std::string, std::string>> expectedAnnotations = {
            {
                {"authorName", ""},
                {"authorAge", "0"},
                {"testBool", "0"},
            },
        };
        AnnotationEmitTest::CheckAnnoDecl(program, annoName, expectedAnnotations);
    }

    void CheckClassAnnotations(pandasm::Program *program)
    {
        const std::string recordName = "A";
        const AnnotationMap expectedClassAnnotations = {
            {"Anno",
             {
                 {"authorName", "Mike"},
                 {"authorAge", "18"},
                 {"testBool", "1"},
             }},
        };
        AnnotationEmitTest::CheckRecordAnnotations(program, recordName, expectedClassAnnotations);
    }

    void CheckFunctionAnnotations(pandasm::Program *program)
    {
        const std::string funcName = "A.foo:void;";
        const AnnotationMap expectedFuncAnnotations = {
            {"Anno",
             {
                 {"authorName", "John"},
                 {"authorAge", "23"},
                 {"testBool", "0"},
             }},
        };
        AnnotationEmitTest::CheckFunctionAnnotations(program, funcName, false, expectedFuncAnnotations);
    }

    void CheckClassPropertyAnnotations(pandasm::Program *program)
    {
        const std::string record = "A";
        const std::string fieldName = "x";
        const AnnotationMap expectedFuncAnnotations = {
            {"Anno",
             {
                 {"authorName", ""},
                 {"authorAge", "0"},
                 {"testBool", "0"},
             }},
        };
        AnnotationEmitTest::CheckClassFieldAnnotations(program, record, fieldName, expectedFuncAnnotations);
    }

private:
    NO_COPY_SEMANTIC(AnnotationsforClass);
    NO_MOVE_SEMANTIC(AnnotationsforClass);
};

TEST_F(AnnotationsforClass, annotations_for_class)
{
    std::string_view text = R"(
    @interface Anno {
        authorName: string = ""
        authorAge: int = 0
        testBool: boolean = false
    }

    @Anno({
        authorName: "Mike",
        authorAge: 18,
        testBool: true
    })
    class A {
        @Anno
        x:int = 1

        @Anno({
            authorName: "John",
            authorAge: 23,
            testBool: false
        })
        foo() {}
    })";

    RunAnnotationEmitTest(text);
}

}  // namespace ark::es2panda::compiler::test