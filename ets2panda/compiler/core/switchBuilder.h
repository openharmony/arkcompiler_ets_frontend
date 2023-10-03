/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_SWITCH_BUILDER_H
#define ES2PANDA_COMPILER_CORE_SWITCH_BUILDER_H

#include "ir/irnode.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/switchCaseStatement.h"
#include "compiler/core/dynamicContext.h"
#include "compiler/core/ETSGen.h"
#include "checker/checker.h"

namespace panda::es2panda::ir {
class SwitchStatement;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::compiler {
class PandaGen;
class Label;

template <typename CodeGen>
class SwitchBuilder {
public:
    SwitchBuilder(CodeGen *cg, const ir::SwitchStatement *stmt)
        : cg_(cg), end_(cg->AllocLabel()), label_ctx_(cg, LabelTarget(end_, LabelTarget::BREAK_LABEL)), stmt_(stmt)
    {
        for (size_t i = 0; i < stmt_->Cases().size(); i++) {
            case_labels_.push_back(cg_->AllocLabel());
        }
    }

    NO_COPY_SEMANTIC(SwitchBuilder);
    NO_MOVE_SEMANTIC(SwitchBuilder);
    ~SwitchBuilder()
    {
        cg_->SetLabel(stmt_, end_);
    }

    void SetCaseTarget(uint32_t index)
    {
        cg_->SetLabel(stmt_->Cases()[index], case_labels_[index]);
    }

    void CompileTagOfSwitch(const VReg tag)
    {
        stmt_->Discriminant()->Compile(cg_);
        if constexpr (std::is_same_v<CodeGen, ETSGen>) {
            cg_->ApplyConversion(stmt_->Discriminant(), stmt_->Discriminant()->TsType());
        }
        cg_->StoreAccumulator(stmt_->Discriminant(), tag);
    }

    void CompileCaseStatements(uint32_t index)
    {
        for (const auto *stmt : stmt_->Cases()[index]->Consequent()) {
            stmt->Compile(cg_);
        }
    }

    void JumpIfCase(const VReg tag, const uint32_t index)
    {
        const auto *const case_target = stmt_->Cases()[index];
        case_target->Test()->Compile(cg_);

        if constexpr (std::is_same_v<CodeGen, PandaGen>) {
            cg_->Condition(case_target, lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL, tag, case_labels_[index]);
        } else {
            const compiler::TargetTypeContext ttctx(cg_, cg_->GetVRegType(tag));
            cg_->Condition(case_target, lexer::TokenType::PUNCTUATOR_NOT_EQUAL, tag, case_labels_[index]);
        }
    }

    void JumpToDefault(uint32_t default_index)
    {
        const ir::SwitchCaseStatement *default_target = stmt_->Cases()[default_index];
        cg_->Branch(default_target, case_labels_[default_index]);
    }

    void Break()
    {
        cg_->Branch(stmt_, end_);
    }

private:
    CodeGen *cg_;
    Label *end_;
    LabelContext label_ctx_;
    const ir::SwitchStatement *stmt_;
    std::vector<Label *> case_labels_;
};
}  // namespace panda::es2panda::compiler

#endif
