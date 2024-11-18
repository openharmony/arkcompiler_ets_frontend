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

#ifndef PANDA_ANNOTATIONS_EMIT_TEST_H
#define PANDA_ANNOTATIONS_EMIT_TEST_H

#include <gtest/gtest.h>
#include "annotation.h"
#include "macros.h"
#include "util/options.h"
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include "assembly-program.h"
namespace ark::es2panda::compiler::test {

using AnnotationMap = std::map<std::string, std::vector<std::pair<std::string, std::string>>>;
using AnnotationValueType = std::variant<bool, uint8_t, uint16_t, uint32_t, uint64_t, float, double, std::string>;
class AnnotationEmitTest : public ::testing::Test {
public:
    AnnotationEmitTest()
    {
        const auto compilerSize = 268435456;

        mem::MemConfig::Initialize(0, 0, compilerSize, 0, 0, 0);
        PoolManager::Initialize(PoolType::MMAP);
    }

    ~AnnotationEmitTest() override
    {
        PoolManager::Finalize();
        mem::MemConfig::Finalize();
    }

protected:
    static constexpr uint32_t COLOR_OPTION_0 = 0;
    static constexpr uint32_t COLOR_OPTION_1 = 1;
    static constexpr double AGE_18 = 18.0;
    static constexpr double AGE_21 = 21.0;
    static constexpr double AGE_32 = 32.0;
    static constexpr double VALUE_1 = 1.0;
    static constexpr double VALUE_2 = 2.0;
    static constexpr double VALUE_3 = 3.0;
    static constexpr double VALUE_4 = 4.0;
    static constexpr double VALUE_5 = 5.0;
    static constexpr double VALUE_6 = 6.0;
    static constexpr double VALUE_7 = 7.0;
    static constexpr double VALUE_8 = 8.0;
    static constexpr double VALUE_9 = 9.0;
    static constexpr uint32_t COLOR_0 = 0;
    static constexpr uint32_t COLOR_1 = 1;
    static constexpr double REVIEWER_AGE_19 = 19.0;
    static constexpr double REVIEWER_AGE_20 = 20.0;
    static constexpr double REVIEWER_AGE_24 = 24.0;

    std::unique_ptr<pandasm::Program> GetCurrentProgram(std::string_view src)
    {
        int argc = 1;
        const char *argv = "../../../../../bin/es2panda";
        static constexpr std::string_view FILE_NAME = "annotation.sts";
        auto program = std::unique_ptr<pandasm::Program>(GetProgram(argc, &argv, FILE_NAME, src));
        return program;
    }

    void CheckAnnoDecl(ark::pandasm::Program *program, const std::string &annoName,
                       const std::vector<std::pair<std::string, std::string>> &expectedAnnotations)
    {
        const auto &recordTable = program->recordTable;
        ASSERT_FALSE(recordTable.empty()) << "No records found in the program.";
        auto found = recordTable.find(annoName);
        ASSERT_NE(found, recordTable.end());

        for (size_t i = 0; i < expectedAnnotations.size(); i++) {
            auto scalarValue = found->second.fieldList[i].metadata->GetValue();
            if (scalarValue) {
                CompareActualWithExpected(expectedAnnotations[i].second, &*scalarValue,
                                          found->second.fieldList[i].name);
            }
        }
    }

    void CheckLiteralArrayTable(
        ark::pandasm::Program *program,
        const std::vector<std::pair<std::string, std::vector<AnnotationValueType>>> &expectedLiteralArrayTable)
    {
        const auto &literalarrayTable = program->literalarrayTable;
        ASSERT_FALSE(literalarrayTable.empty()) << "literalarrayTable is empty!";
        for (const auto &literalArray : expectedLiteralArrayTable) {
            auto found = literalarrayTable.find(literalArray.first);
            ASSERT_NE(found, literalarrayTable.end());
            size_t i = 1;
            for (const auto &value : literalArray.second) {
                constexpr int STRIDE = 2;
                ASSERT_EQ(value, found->second.literals[i].value) << "Value mismatch for " + literalArray.first;
                i += STRIDE;
            }
        }
    }

    void CheckClassAnnotations(ark::pandasm::Program *program, const std::string &className,
                               const AnnotationMap &expectedAnnotations)
    {
        const auto &recordTable = program->recordTable;
        ASSERT_FALSE(recordTable.empty()) << "No records found in the program.";
        auto found = recordTable.find(className);
        ASSERT_NE(found, recordTable.end());

        for (const auto &anno : found->second.metadata->GetAnnotations()) {
            auto it = expectedAnnotations.find(anno.GetName());
            ASSERT_NE(it, expectedAnnotations.end()) << "Unexpected annotation: " << anno.GetName();

            // Check the fields for the matched annotation name
            CheckAnnotation(it->second, anno);
        }
    }

    void CheckFunctionAnnotations(ark::pandasm::Program *program, const std::string &functionName,
                                  const AnnotationMap &expectedAnnotations)
    {
        const auto &functionTable = program->functionTable;
        auto found = functionTable.find(functionName);
        ASSERT_NE(found, functionTable.end());

        for (const auto &annotation : found->second.metadata->GetAnnotations()) {
            auto it = expectedAnnotations.find(annotation.GetName());
            ASSERT_NE(it, expectedAnnotations.end()) << "Unexpected annotation: " << annotation.GetName();

            // Check the fields for the matched annotation name
            CheckAnnotation(it->second, annotation);
        }
    }

    void CompareActualWithExpected(const std::string &expectedValue, pandasm::ScalarValue *scalarValue,
                                   const std::string &field) const
    {
        std::string actualValue = std::visit(
            [](const auto &value) -> std::string {
                using ValueType = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<ValueType, std::string>) {
                    return value;
                } else if constexpr (std::is_arithmetic_v<ValueType>) {
                    return std::to_string(value);
                } else {
                    return "Unsupported type";
                }
            },
            scalarValue->GetValue());

        ASSERT_EQ(actualValue, expectedValue) << "Value mismatch for " + field;
    }

    void CheckAnnotation(const std::vector<std::pair<std::string, std::string>> &expectedValues,
                         const pandasm::AnnotationData &annotation) const
    {
        for (const auto &element : annotation.GetElements()) {
            auto it = std::find_if(expectedValues.begin(), expectedValues.end(),
                                   [&element](const auto &pair) { return pair.first == element.GetName(); });
            if (it != expectedValues.end()) {
                CompareActualWithExpected(it->second, element.GetValue()->GetAsScalar(), element.GetName());
            }
        }
    }

    static pandasm::Program *GetProgram(int argc, const char **argv, std::string_view fileName, std::string_view src)
    {
        auto options = std::make_unique<util::Options>();
        if (!options->Parse(argc, argv)) {
            std::cerr << options->ErrorMsg() << std::endl;
            return nullptr;
        }

        ark::Logger::ComponentMask mask {};
        mask.set(ark::Logger::Component::ES2PANDA);
        ark::Logger::InitializeStdLogging(ark::Logger::LevelFromString(options->LogLevel()), mask);

        ark::es2panda::Compiler compiler(options->Extension(), options->ThreadCount());
        ark::es2panda::SourceFile input(fileName, src, options->ParseModule());
        auto program = compiler.Compile(input, *options);
        return program;
    }

private:
    NO_COPY_SEMANTIC(AnnotationEmitTest);
    NO_MOVE_SEMANTIC(AnnotationEmitTest);
};

}  // namespace ark::es2panda::compiler::test

#endif  // PANDA_ANNOTATIONS_EMIT_TEST_H
