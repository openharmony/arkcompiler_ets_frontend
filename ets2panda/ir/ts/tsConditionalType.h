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

#ifndef ES2PANDA_IR_TS_CONDITIONAL_TYPE_H
#define ES2PANDA_IR_TS_CONDITIONAL_TYPE_H

#include "plugins/ecmascript/es2panda/ir/typeNode.h"

namespace panda::es2panda::ir {
class TSConditionalType : public TypeNode {
public:
    explicit TSConditionalType(Expression *check_type, Expression *extends_type, Expression *true_type,
                               Expression *false_type)
        : TypeNode(AstNodeType::TS_CONDITIONAL_TYPE),
          check_type_(check_type),
          extends_type_(extends_type),
          true_type_(true_type),
          false_type_(false_type)
    {
    }

    const Expression *CheckType() const
    {
        return check_type_;
    }

    const Expression *ExtendsType() const
    {
        return extends_type_;
    }

    const Expression *TrueType() const
    {
        return true_type_;
    }

    const Expression *FalseType() const
    {
        return false_type_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *check_type_;
    Expression *extends_type_;
    Expression *true_type_;
    Expression *false_type_;
};
}  // namespace panda::es2panda::ir

#endif
