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

#ifndef ES2PANDA_IR_TS_TYPE_REFERENCE_H
#define ES2PANDA_IR_TS_TYPE_REFERENCE_H

#include "ir/typeNode.h"

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class TSTypeParameterInstantiation;

class TSTypeReference : public TypeNode {
public:
    explicit TSTypeReference(Expression *type_name, TSTypeParameterInstantiation *type_params)
        : TypeNode(AstNodeType::TS_TYPE_REFERENCE), type_name_(type_name), type_params_(type_params)
    {
    }

    const TSTypeParameterInstantiation *TypeParams() const
    {
        return type_params_;
    }

    const Expression *TypeName() const
    {
        return type_name_;
    }

    ir::Identifier *BaseName() const;

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *type_name_;
    TSTypeParameterInstantiation *type_params_;
};
}  // namespace panda::es2panda::ir

#endif
