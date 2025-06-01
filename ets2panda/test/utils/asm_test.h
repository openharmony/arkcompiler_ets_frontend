/**
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

#ifndef ES2PANDA_TEST_UTILS_ASM_TEST_H
#define ES2PANDA_TEST_UTILS_ASM_TEST_H

#include "compiler/lowering/phase.h"
#include "util/options.h"
#include <gtest/gtest.h>

namespace util_alias = ark::es2panda::util;

using AnnotationMap = std::map<std::string, std::vector<std::pair<std::string, std::string>>>;
using AnnotationValueType = std::variant<bool, uint8_t, uint16_t, uint32_t, uint64_t, float, double, std::string>;

namespace test::utils {

class AsmTest : public testing::Test {
public:
    AsmTest();
    ~AsmTest() override;

    static std::unique_ptr<ark::pandasm::Program> GetProgram(int argc, char const *const *argv,
                                                             std::string_view fileName, std::string_view src)
    {
        auto de = util_alias::DiagnosticEngine();
        auto options = std::make_unique<util_alias::Options>(
            argv[0], de);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        if (!options->Parse(ark::Span(argv, argc))) {
            return nullptr;
        }

        ark::Logger::ComponentMask mask {};
        mask.set(ark::Logger::Component::ES2PANDA);
        ark::Logger::InitializeStdLogging(options->LogLevel(), mask);

        ark::es2panda::Compiler compiler(options->GetExtension(), options->GetThread());
        ark::es2panda::SourceFile input(fileName, src, options->IsModule());

        return std::unique_ptr<ark::pandasm::Program>(compiler.Compile(input, *options, de));
    }

    ark::pandasm::Function *GetFunction(std::string_view functionName,
                                        const std::map<std::string, ark::pandasm::Function> &table);
    ark::pandasm::Record *GetRecord(std::string_view recordName, const std::unique_ptr<ark::pandasm::Program> &program);
    void CompareActualWithExpected(const std::string &expectedValue, ark::pandasm::ScalarValue *scalarValue,
                                   const std::string &field);

    void CheckAnnoDecl(ark::pandasm::Program *program, const std::string &annoName,
                       const std::vector<std::pair<std::string, std::string>> &expectedAnnotations);

    void CheckLiteralArrayTable(
        ark::pandasm::Program *program,
        const std::vector<std::pair<std::string, std::vector<AnnotationValueType>>> &expectedLiteralArrayTable);

    void CheckAnnotation(const std::vector<std::pair<std::string, std::string>> &expectedValues,
                         const ark::pandasm::AnnotationData &annotation);

    void CheckRecordAnnotations(ark::pandasm::Program *program, const std::string &recordName,
                                const AnnotationMap &expectedAnnotations);

    void CheckModuleAnnotation(ark::pandasm::Program *program, const std::string &recordName, bool isModule,
                               const std::vector<std::string> &expectedAnnotations = {});

    void CheckRecordWithoutAnnotations(ark::pandasm::Program *program, const std::string &recordName,
                                       bool isModule = false);

    void CheckFunctionAnnotations(ark::pandasm::Program *program, const std::string &functionName, bool isStatic,
                                  const AnnotationMap &expectedAnnotations);

    void CheckFunctionWithoutAnnotations(ark::pandasm::Program *program, const std::string &functionName,
                                         bool isStatic);

    void CheckFunctionParameterAnnotations(ark::pandasm::Program *program, const std::string &functionName,
                                           bool isStatic, const uint32_t &paramIndex,
                                           const AnnotationMap &expectedAnnotations);

    void CheckFunctionParameterWithoutAnnotations(ark::pandasm::Program *program, const std::string &functionName,
                                                  bool isStatic, const uint32_t &paramIndex);

    void CheckClassFieldAnnotations(ark::pandasm::Program *program, const std::string &recordName,
                                    const std::string &fieldName, const AnnotationMap &expectedAnnotations);

    void CheckClassFieldWithoutAnnotations(ark::pandasm::Program *program, const std::string &recordName,
                                           const std::string &fieldName);

    void SetCurrentProgram(std::string_view src);

    std::unique_ptr<ark::pandasm::Program> GetCurrentProgram(std::string_view src);

    NO_COPY_SEMANTIC(AsmTest);
    NO_MOVE_SEMANTIC(AsmTest);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    std::unique_ptr<ark::pandasm::Program> program_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

}  // namespace test::utils

#endif  // ES2PANDA_TEST_UTILS_ASM_TEST_H
