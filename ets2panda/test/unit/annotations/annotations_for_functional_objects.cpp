/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

class AnnotationsforFunctionalObjects : public AnnotationEmitTest {
public:
    AnnotationsforFunctionalObjects() = default;

    ~AnnotationsforFunctionalObjects() override = default;

    void RunAnnotationEmitTest(const std::string_view text)
    {
        auto program = GetCurrentProgram(text);
        ASSERT_NE(program, nullptr);

        CheckAnnotations(program.get());
        CheckClassAnnotations(program.get());
    }

    void CheckAnnotations(pandasm::Program *program)
    {
        const std::string annoName = "std.annotations.InterfaceObjectLiteral";
        AnnotationEmitTest::CheckAnnoDecl(program, annoName, {});
    }

    void CheckClassAnnotations(pandasm::Program *program)
    {
        const std::string recordName = "Iface$ObjectLiteral";
        const AnnotationMap expectedClassAnnotations = {
            {"std.annotations.InterfaceObjectLiteral", {}},
        };
        AnnotationEmitTest::CheckRecordAnnotations(program, recordName, expectedClassAnnotations);
    }

private:
    NO_COPY_SEMANTIC(AnnotationsforFunctionalObjects);
    NO_MOVE_SEMANTIC(AnnotationsforFunctionalObjects);
};

// #22952
TEST_F(AnnotationsforFunctionalObjects, annotations_for_functional_objects)
{
    std::string_view text = R"(
    interface Iface { a: number }

    function bar() {
        let tif: Iface = { a: 42 }
    })";

    RunAnnotationEmitTest(text);
}

}  // namespace ark::es2panda::compiler::test
