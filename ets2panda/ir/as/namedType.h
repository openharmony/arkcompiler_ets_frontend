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

#ifndef ES2PANDA_IR_NAMED_TYPE_H
#define ES2PANDA_IR_NAMED_TYPE_H

#include "plugins/ecmascript/es2panda/ir/typeNode.h"

namespace panda::es2panda::ir {
class Identifier;
class TSTypeParameterInstantiation;

class NamedType : public TypeNode {
public:
    explicit NamedType(Identifier *name) : TypeNode(AstNodeType::NAMED_TYPE), name_(name) {}

    const Identifier *Name() const
    {
        return name_;
    }

    const TSTypeParameterInstantiation *TypeParams() const
    {
        return type_params_;
    }

    bool IsNullable() const
    {
        return nullable_;
    }

    void SetNullable(bool nullable)
    {
        nullable_ = nullable;
    }

    void SetNext(NamedType *next)
    {
        next_ = next;
    }

    void SetTypeParams(TSTypeParameterInstantiation *type_params)
    {
        type_params_ = type_params;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;

    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Identifier *name_;
    TSTypeParameterInstantiation *type_params_ {};
    NamedType *next_ {};
    bool nullable_ {};
};
}  // namespace panda::es2panda::ir

#endif
