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

#ifndef ES2PANDA_IR_TS_TYPE_PARAMETER_H
#define ES2PANDA_IR_TS_TYPE_PARAMETER_H

#include "ir/expression.h"

namespace panda::es2panda::ir {
class Identifier;

class TSTypeParameter : public Expression {
public:
    explicit TSTypeParameter(Identifier *name, TypeNode *constraint, TypeNode *default_type)
        : Expression(AstNodeType::TS_TYPE_PARAMETER), name_(name), constraint_(constraint), default_type_(default_type)
    {
    }

    explicit TSTypeParameter(Identifier *name, TypeNode *constraint, TypeNode *default_type, ModifierFlags flags)
        : Expression(AstNodeType::TS_TYPE_PARAMETER, flags),
          name_(name),
          constraint_(constraint),
          default_type_(default_type)
    {
        ASSERT(flags == ModifierFlags::NONE || flags == ModifierFlags::IN || flags == ModifierFlags::OUT);
    }

    const Identifier *Name() const
    {
        return name_;
    }

    TypeNode *Constraint()
    {
        return constraint_;
    }

    const TypeNode *Constraint() const
    {
        return constraint_;
    }

    const TypeNode *DefaultType() const
    {
        return default_type_;
    }

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Identifier *name_;
    TypeNode *constraint_;
    TypeNode *default_type_;
};
}  // namespace panda::es2panda::ir

#endif
