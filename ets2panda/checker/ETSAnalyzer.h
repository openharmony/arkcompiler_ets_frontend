/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_CHECKER_ETSANALYZER_H
#define ES2PANDA_CHECKER_ETSANALYZER_H

#include "checker/SemanticAnalyzer.h"

namespace panda::es2panda::checker {

class ETSAnalyzer final : public SemanticAnalyzer {
public:
    explicit ETSAnalyzer(Checker *checker) : SemanticAnalyzer(checker) {};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_ETSANALYZER_CHECK_METHOD(_, nodeType) checker::Type *Check(ir::nodeType *node) const override;
    AST_NODE_MAPPING(DECLARE_ETSANALYZER_CHECK_METHOD)
#undef DECLARE_ETSANALYZER_CHECK_METHOD

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_ETSANALYZER_CHECK_METHOD(_, __, nodeType, ___) \
    virtual checker::Type *Check(ir::nodeType *node) const override;
    AST_NODE_REINTERPRET_MAPPING(DECLARE_ETSANALYZER_CHECK_METHOD)
#undef DECLARE_ETSANALYZER_CHECK_METHOD

private:
    ETSChecker *GetETSChecker() const;
};

}  // namespace panda::es2panda::checker

#endif  // ES2PANDA_CHECKER_ETSANALYZER_H
