/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RULES_H
#define RULES_H

#include <vector>
#include "rule.h"

namespace ark::es2panda::lsp {

struct RuleSpec {
public:
    explicit RuleSpec(Rule &rule, std::vector<TokenRange> &leftTokenRange, std::vector<TokenRange> &rightTokenRange)
        : rule_(rule), leftTokenRange_(leftTokenRange), rightTokenRange_(rightTokenRange)
    {
    }

    Rule &GetRule()
    {
        return rule_;
    }

    const Rule &GetRule() const
    {
        return rule_;
    }

    std::vector<TokenRange> &GetLeftTokenRange()
    {
        return leftTokenRange_;
    }

    const std::vector<TokenRange> &GetLeftTokenRange() const
    {
        return leftTokenRange_;
    }

    std::vector<TokenRange> &GetRightTokenRange()
    {
        return rightTokenRange_;
    }

    const std::vector<TokenRange> &GetRightTokenRange() const
    {
        return rightTokenRange_;
    }

private:
    Rule rule_;
    std::vector<TokenRange> leftTokenRange_;
    std::vector<TokenRange> rightTokenRange_;
};

std::vector<RuleSpec> GetAllRules();

}  // namespace ark::es2panda::lsp

#endif