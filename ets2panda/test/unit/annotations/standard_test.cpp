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
#include "annotation.h"
#include "util/options.h"
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include "assembly-program.h"
#include "test/unit/annotations/annotations_emit_test.h"

namespace ark::es2panda::compiler::test {

class StandardEmitTest : public AnnotationEmitTest {
public:
    StandardEmitTest() = default;

    ~StandardEmitTest() override = default;

    void RunAnnotationEmitTest(const std::string_view text)
    {
        auto program = GetCurrentProgram(text);
        ASSERT_NE(program, nullptr);

        CheckAnnotations(program.get());
        CheckClassAnnotations(program.get());
        CheckFunctionAnnotations(program.get());
        CheckLiteralArrayTable(program.get());
    }

    void CheckAnnotations(pandasm::Program *program)
    {
        const std::string annoName = "ClassAuthor";
        const std::vector<std::pair<std::string, std::string>> expectedAnnotations = {
            {"authorName", "Jim"},
            {"authorAge", "35.000000"},
            {"testBool", "0"},
            {"favorColor", "1"},
            {"color", "ETSGLOBAL$ClassAuthor$color$0"},
            {"reviewers", "ETSGLOBAL$ClassAuthor$reviewers$1"},
            {"reviewersAge", "ETSGLOBAL$ClassAuthor$reviewersAge$2"},
            {"testBools", "ETSGLOBAL$ClassAuthor$testBools$3"},
            {"mutiArray", "ETSGLOBAL$ClassAuthor$mutiArray$7"},
        };
        AnnotationEmitTest::CheckAnnoDecl(program, annoName, expectedAnnotations);
    }

    void CheckClassAnnotations(pandasm::Program *program)
    {
        const std::string recordName = "MyClass";
        const AnnotationMap expectedClassAnnotations = {
            {"ClassAuthor",
             {
                 {"authorName", "Jim"},
                 {"authorAge", "35.000000"},
                 {"testBool", "0"},
                 {"favorColor", "1"},
                 {"color", "MyClass$ClassAuthor$color$12"},
                 {"reviewers", "MyClass$ClassAuthor$reviewers$14"},
                 {"reviewersAge", "MyClass$ClassAuthor$reviewersAge$15"},
                 {"testBools", "MyClass$ClassAuthor$testBools$13"},
                 {"mutiArray", "MyClass$ClassAuthor$mutiArray$11"},
             }},
        };
        AnnotationEmitTest::CheckRecordAnnotations(program, recordName, expectedClassAnnotations);
    }

    void CheckFunctionAnnotations(pandasm::Program *program)
    {
        const std::string functionName = "MyClass.foo:void;";
        const AnnotationMap expectedFuncAnnotations = {
            {"ClassAuthor",
             {
                 {"mutiArray", "MyClass.foo:void;$ClassAuthor$mutiArray$19"},
                 {"color", "MyClass.foo:void;$ClassAuthor$color$20"},
                 {"testBools", "MyClass.foo:void;$ClassAuthor$testBools$21"},
                 {"reviewers", "MyClass.foo:void;$ClassAuthor$reviewers$22"},
                 {"favorColor", "1"},
                 {"testBool", "0"},
                 {"reviewersAge", "MyClass.foo:void;$ClassAuthor$reviewersAge$23"},
                 {"authorAge", "35.000000"},
                 {"authorName", "Jim"},
             }},
        };
        AnnotationEmitTest::CheckFunctionAnnotations(program, functionName, false, expectedFuncAnnotations);
    }

    void CheckLiteralArrayTable(pandasm::Program *program)
    {
        std::vector<std::pair<std::string, std::vector<AnnotationValueType>>> expectedLiteralArrayTable = {
            {"ETSGLOBAL$ClassAuthor$color$0", std::vector<AnnotationValueType> {COLOR_OPTION_0, COLOR_OPTION_1}},
            {"ETSGLOBAL$ClassAuthor$reviewers$1",
             std::vector<AnnotationValueType> {std::string("Bob"), std::string("Jim"), std::string("Tom")}},
            {"ETSGLOBAL$ClassAuthor$reviewersAge$2", std::vector<AnnotationValueType> {AGE_18, AGE_21, AGE_32}},
            {"ETSGLOBAL$ClassAuthor$testBools$3", std::vector<AnnotationValueType> {false, true, false}},
            {"ETSGLOBAL$ClassAuthor$mutiArray$4", std::vector<AnnotationValueType> {VALUE_1, VALUE_2, VALUE_3}},
            {"ETSGLOBAL$ClassAuthor$mutiArray$5", std::vector<AnnotationValueType> {VALUE_4, VALUE_5, VALUE_6}},
            {"ETSGLOBAL$ClassAuthor$mutiArray$6", std::vector<AnnotationValueType> {VALUE_7, VALUE_8, VALUE_9}},
            {"ETSGLOBAL$ClassAuthor$mutiArray$7",
             std::vector<AnnotationValueType> {std::string("ETSGLOBAL$ClassAuthor$mutiArray$4"),
                                               std::string("ETSGLOBAL$ClassAuthor$mutiArray$5"),
                                               std::string("ETSGLOBAL$ClassAuthor$mutiArray$6")}},
            {"MyClass$ClassAuthor$color$12", std::vector<AnnotationValueType> {COLOR_OPTION_0, COLOR_OPTION_1}},
            {"MyClass$ClassAuthor$reviewers$14",
             std::vector<AnnotationValueType> {std::string("Bob"), std::string("Jim"), std::string("Tom")}},
            {"MyClass$ClassAuthor$reviewersAge$15", std::vector<AnnotationValueType> {AGE_18, AGE_21, AGE_32}},
            {"MyClass$ClassAuthor$testBools$13", std::vector<AnnotationValueType> {false, true, false}},
            {"MyClass$ClassAuthor$mutiArray$8", std::vector<AnnotationValueType> {VALUE_1, VALUE_2, VALUE_3}},
            {"MyClass$ClassAuthor$mutiArray$9", std::vector<AnnotationValueType> {VALUE_4, VALUE_5, VALUE_6}},
            {"MyClass$ClassAuthor$mutiArray$10", std::vector<AnnotationValueType> {VALUE_7, VALUE_8, VALUE_9}},
            {"MyClass$ClassAuthor$mutiArray$11",
             std::vector<AnnotationValueType> {std::string("MyClass$ClassAuthor$mutiArray$8"),
                                               std::string("MyClass$ClassAuthor$mutiArray$9"),
                                               std::string("MyClass$ClassAuthor$mutiArray$10")}},
            {"MyClass.foo:void;$ClassAuthor$color$20",
             std::vector<AnnotationValueType> {COLOR_OPTION_0, COLOR_OPTION_1}},
            {"MyClass.foo:void;$ClassAuthor$reviewers$22",
             std::vector<AnnotationValueType> {std::string("Bob"), std::string("Jim"), std::string("Tom")}},
            {"MyClass.foo:void;$ClassAuthor$reviewersAge$23",
             std::vector<AnnotationValueType> {AGE_18, AGE_21, AGE_32}},
            {"MyClass.foo:void;$ClassAuthor$testBools$21", std::vector<AnnotationValueType> {false, true, false}},
            {"MyClass.foo:void;$ClassAuthor$mutiArray$16",
             std::vector<AnnotationValueType> {VALUE_1, VALUE_2, VALUE_3}},
            {"MyClass.foo:void;$ClassAuthor$mutiArray$17",
             std::vector<AnnotationValueType> {VALUE_4, VALUE_5, VALUE_6}},
            {"MyClass.foo:void;$ClassAuthor$mutiArray$18",
             std::vector<AnnotationValueType> {VALUE_7, VALUE_8, VALUE_9}},
            {"MyClass.foo:void;$ClassAuthor$mutiArray$19",
             std::vector<AnnotationValueType> {std::string("MyClass.foo:void;$ClassAuthor$mutiArray$16"),
                                               std::string("MyClass.foo:void;$ClassAuthor$mutiArray$17"),
                                               std::string("MyClass.foo:void;$ClassAuthor$mutiArray$18")}},
        };

        AnnotationEmitTest::CheckLiteralArrayTable(program, expectedLiteralArrayTable);
    }

private:
    NO_COPY_SEMANTIC(StandardEmitTest);
    NO_MOVE_SEMANTIC(StandardEmitTest);
};

TEST_F(StandardEmitTest, standard_test)
{
    std::string_view text = R"(
        enum Color{RED, BLUE, GREEN}

        @interface ClassAuthor {
        authorName: string = "Jim"
        authorAge: number = 35
        testBool: boolean = false
        favorColor: Color = Color.BLUE
        color: FixedArray<Color> = [Color.RED, Color.BLUE]
        reviewers: FixedArray<string> = ["Bob", "Jim", "Tom"]
        reviewersAge: FixedArray<number> = [18, 21, 32]
        testBools: FixedArray<boolean> = [false, true, false]
        mutiArray: FixedArray<FixedArray<number>> = [
            [1, 2, 3],
            [4, 5, 6],
            [7, 8, 9]
        ]
    }
    @ClassAuthor()
    class MyClass {
        @ClassAuthor()
        foo() {}
    })";

    RunAnnotationEmitTest(text);
}

}  // namespace ark::es2panda::compiler::test
