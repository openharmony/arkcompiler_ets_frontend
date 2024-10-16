/*
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
#include <string>
#include <utility>
#include <vector>
#include "assembly-program.h"
#include "test/unit/annotations/annotations_emit_test.h"

namespace ark::es2panda::compiler::test {

class MutipleAnnotationsforFunction : public AnnotationEmitTest {
public:
    MutipleAnnotationsforFunction() = default;

    ~MutipleAnnotationsforFunction() override = default;

    void RunAnnotationEmitTest(const std::string_view text)
    {
        auto program = GetCurrentProgram(text);
        ASSERT_NE(program, nullptr);

        CheckAnnotations(program.get());
        CheckFunctionAnnotations(program.get());
        CheckLiteralArrayTable(program.get());
    }

    void CheckAnnotations(pandasm::Program *program)
    {
        const std::string annoName0 = "Anno1";
        const std::vector<std::pair<std::string, std::string>> expectedAnnotation0 = {
            {
                {"param", "1"},
            },
        };
        CheckAnnoDecl(program, annoName0, expectedAnnotation0);

        const std::string annoName1 = "Anno2";
        const std::vector<std::pair<std::string, std::string>> expectedAnnotation1 = {
            {
                {"param", "ETSGLOBAL$Anno2$param$0"},
            },
        };
        CheckAnnoDecl(program, annoName1, expectedAnnotation1);

        const std::string annoName2 = "Anno3";
        const std::vector<std::pair<std::string, std::string>> expectedAnnotation2 = {
            {
                {"param", "ETSGLOBAL$Anno3$param$10"},
            },
        };
        CheckAnnoDecl(program, annoName2, expectedAnnotation2);
    }

    void CheckFunctionAnnotations(pandasm::Program *program)
    {
        const std::string functionName = "ETSGLOBAL.foo:void;";
        const AnnotationMap expectedFuncAnnotations = {{"Anno1",
                                                        {
                                                            {"value", "2"},
                                                        }},
                                                       {"Anno2",
                                                        {
                                                            {"value", "foo$Anno2$value$11"},
                                                        }},
                                                       {"Anno3",
                                                        {
                                                            {"param", "foo$Anno3$param$21"},
                                                        }}};
        AnnotationEmitTest::CheckFunctionAnnotations(program, functionName, expectedFuncAnnotations);
    }

    void CheckLiteralArrayTable(pandasm::Program *program)
    {
        std::vector<std::pair<std::string, std::vector<AnnotationValueType>>> expectedLiteralArrayTable = {
            {"ETSGLOBAL$Anno2$param$0", std::vector<AnnotationValueType> {VALUE_1, VALUE_2, VALUE_3, VALUE_4}},
            {"ETSGLOBAL$Anno3$param$1", std::vector<AnnotationValueType> {VALUE_1}},
            {"ETSGLOBAL$Anno3$param$2", std::vector<AnnotationValueType> {VALUE_2}},
            {"ETSGLOBAL$Anno3$param$3", std::vector<AnnotationValueType> {std::string("ETSGLOBAL$Anno3$param$1"),
                                                                          std::string("ETSGLOBAL$Anno3$param$2")}},
            {"ETSGLOBAL$Anno3$param$4", std::vector<AnnotationValueType> {VALUE_2}},
            {"ETSGLOBAL$Anno3$param$5", std::vector<AnnotationValueType> {VALUE_3}},
            {"ETSGLOBAL$Anno3$param$6", std::vector<AnnotationValueType> {std::string("ETSGLOBAL$Anno3$param$4"),
                                                                          std::string("ETSGLOBAL$Anno3$param$5")}},
            {"ETSGLOBAL$Anno3$param$7", std::vector<AnnotationValueType> {VALUE_3}},
            {"ETSGLOBAL$Anno3$param$8", std::vector<AnnotationValueType> {VALUE_4}},
            {"ETSGLOBAL$Anno3$param$9", std::vector<AnnotationValueType> {std::string("ETSGLOBAL$Anno3$param$7"),
                                                                          std::string("ETSGLOBAL$Anno3$param$8")}},
            {"ETSGLOBAL$Anno3$param$10", std::vector<AnnotationValueType> {std::string("ETSGLOBAL$Anno3$param$3"),
                                                                           std::string("ETSGLOBAL$Anno3$param$6"),
                                                                           std::string("ETSGLOBAL$Anno3$param$9")}},
            {"foo$Anno2$value$11", std::vector<AnnotationValueType> {VALUE_4, VALUE_5, VALUE_6, VALUE_7}},
            {"foo$Anno3$param$12", std::vector<AnnotationValueType> {VALUE_1}},
            {"foo$Anno3$param$13", std::vector<AnnotationValueType> {VALUE_2}},
            {"foo$Anno3$param$14",
             std::vector<AnnotationValueType> {std::string("foo$Anno3$param$12"), std::string("foo$Anno3$param$13")}},
            {"foo$Anno3$param$15", std::vector<AnnotationValueType> {VALUE_2}},
            {"foo$Anno3$param$16", std::vector<AnnotationValueType> {VALUE_3}},
            {"foo$Anno3$param$17",
             std::vector<AnnotationValueType> {std::string("foo$Anno3$param$15"), std::string("foo$Anno3$param$16")}},
            {"foo$Anno3$param$18", std::vector<AnnotationValueType> {VALUE_3}},
            {"foo$Anno3$param$19", std::vector<AnnotationValueType> {VALUE_4}},
            {"foo$Anno3$param$20",
             std::vector<AnnotationValueType> {std::string("foo$Anno3$param$18"), std::string("foo$Anno3$param$19")}},
            {"foo$Anno3$param$21",
             std::vector<AnnotationValueType> {std::string("foo$Anno3$param$14"), std::string("foo$Anno3$param$17"),
                                               std::string("foo$Anno3$param$20")}},
        };

        AnnotationEmitTest::CheckLiteralArrayTable(program, expectedLiteralArrayTable);
    }

private:
    NO_COPY_SEMANTIC(MutipleAnnotationsforFunction);
    NO_MOVE_SEMANTIC(MutipleAnnotationsforFunction);
};

TEST_F(MutipleAnnotationsforFunction, mutiple_annotations_for_function)
{
    std::string_view text = R"(
        @interface Anno1 {
            param: int = 1
        }

        @interface Anno2 {
            param: int[] = [1, 2, 3, 4]
        }

        @interface Anno3 {
            param: int[][][] = [[[1], [2]], [[2], [3]], [[3], [4]]]
        }

        @Anno1(2)
        @Anno2([4, 5, 6, 7])
        @Anno3
        function foo() {}
    )";

    RunAnnotationEmitTest(text);
}

}  // namespace ark::es2panda::compiler::test