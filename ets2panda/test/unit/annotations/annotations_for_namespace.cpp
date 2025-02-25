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

class AnnotationsforNamespace : public AnnotationEmitTest {
public:
    AnnotationsforNamespace() = default;

    ~AnnotationsforNamespace() override = default;

    void RunAnnotationEmitTest(const std::string_view text)
    {
        auto program = GetCurrentProgram(text);
        ASSERT_NE(program, nullptr);

        CheckAnnotations(program.get());
        CheckNamespaceAnnotations(program.get());
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

    void CheckNamespaceAnnotations(pandasm::Program *program)
    {
        const std::string recordName1 = "A";
        const AnnotationMap expectedClassAnnotations1 = {
            {"Anno",
             {
                 {"authorName", "Mike"},
                 {"authorAge", "18"},
                 {"testBool", "1"},
             }},
        };
        const std::string recordName2 = "A.B";
        const AnnotationMap expectedClassAnnotations2 = {
            {"Anno",
             {
                 {"authorName", ""},
                 {"authorAge", "0"},
                 {"testBool", "0"},
             }},
        };
        AnnotationEmitTest::CheckRecordAnnotations(program, recordName1, expectedClassAnnotations1);
        AnnotationEmitTest::CheckRecordAnnotations(program, recordName2, expectedClassAnnotations2);
    }

private:
    NO_COPY_SEMANTIC(AnnotationsforNamespace);
    NO_MOVE_SEMANTIC(AnnotationsforNamespace);
};

TEST_F(AnnotationsforNamespace, annotations_for_namespace)
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
    namespace A {
        @Anno()
        namespace B {}
    })";

    RunAnnotationEmitTest(text);
}

}  // namespace ark::es2panda::compiler::test