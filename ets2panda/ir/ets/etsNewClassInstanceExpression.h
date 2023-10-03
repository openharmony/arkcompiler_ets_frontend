/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_ETS_NEW_CLASS_INSTANCE_EXPRESSION_H
#define ES2PANDA_IR_ETS_NEW_CLASS_INSTANCE_EXPRESSION_H

#include "compiler/core/vReg.h"
#include "ir/expression.h"

namespace panda::es2panda::checker {
class Signature;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::ir {

class ClassDefinition;

class ETSNewClassInstanceExpression : public Expression {
public:
    explicit ETSNewClassInstanceExpression(ir::Expression *type_reference, ArenaVector<ir::Expression *> &&arguments,
                                           ir::ClassDefinition *class_definition)
        : Expression(AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION),
          type_reference_(type_reference),
          arguments_(std::move(arguments)),
          class_def_(class_definition)
    {
    }

    ir::ClassDefinition *ClassDefinition()
    {
        return class_def_;
    }

    const ir::ClassDefinition *ClassDefinition() const
    {
        return class_def_;
    }

    ir::Expression *GetTypeRef() const
    {
        return type_reference_;
    }

    ArenaVector<ir::Expression *> GetArguments() const
    {
        return arguments_;
    }

    void SetSignature(checker::Signature *const signature) noexcept
    {
        signature_ = signature;
    }

    static void CreateDynamicObject(const ir::AstNode *node, compiler::ETSGen *etsg, compiler::VReg &obj_reg,
                                    ir::Expression *name, checker::Signature *signature,
                                    const ArenaVector<ir::Expression *> &arguments);

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    ir::Expression *type_reference_;
    ArenaVector<ir::Expression *> arguments_;
    ir::ClassDefinition *class_def_;
    checker::Signature *signature_ {};
};
}  // namespace panda::es2panda::ir

#endif
