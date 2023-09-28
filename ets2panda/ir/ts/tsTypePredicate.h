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

#ifndef ES2PANDA_IR_TS_TYPE_PREDICATE_H
#define ES2PANDA_IR_TS_TYPE_PREDICATE_H

#include "plugins/ecmascript/es2panda/ir/typeNode.h"

namespace panda::es2panda::ir {
class TSTypePredicate : public TypeNode {
public:
    explicit TSTypePredicate(Expression *parameter_name, TypeNode *type_annotation, bool asserts)
        : TypeNode(AstNodeType::TS_TYPE_PREDICATE),
          parameter_name_(parameter_name),
          type_annotation_(type_annotation),
          asserts_(asserts)
    {
    }

    Expression *ParameterName() const
    {
        return parameter_name_;
    }

    TypeNode *TypeAnnotation() const
    {
        return type_annotation_;
    }

    bool Asserts() const
    {
        return asserts_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *parameter_name_;
    TypeNode *type_annotation_;
    bool asserts_;
};
}  // namespace panda::es2panda::ir

#endif
