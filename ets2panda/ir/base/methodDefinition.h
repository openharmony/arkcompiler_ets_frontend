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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_METHOD_DEFINITION_H
#define ES2PANDA_PARSER_INCLUDE_AST_METHOD_DEFINITION_H

#include "checker/types/ets/etsObjectType.h"
#include "checker/types/signature.h"
#include "ir/base/classElement.h"

namespace panda::es2panda::ir {
class Expression;

enum class MethodDefinitionKind { NONE, CONSTRUCTOR, METHOD, EXTENSION_METHOD, GET, SET };

class MethodDefinition : public ClassElement {
public:
    explicit MethodDefinition(MethodDefinitionKind kind, Expression *key, Expression *value, ModifierFlags modifiers,
                              ArenaAllocator *allocator, bool is_computed)
        : ClassElement(AstNodeType::METHOD_DEFINITION, key, value, modifiers, allocator, is_computed),
          kind_(kind),
          overloads_(allocator->Adapter())
    {
    }

    MethodDefinitionKind Kind() const
    {
        return kind_;
    }

    bool IsConstructor() const
    {
        return kind_ == MethodDefinitionKind::CONSTRUCTOR;
    }

    bool IsExtensionMethod() const
    {
        return kind_ == MethodDefinitionKind::EXTENSION_METHOD;
    }

    const ArenaVector<MethodDefinition *> &Overloads() const
    {
        return overloads_;
    }

    void SetOverloads(ArenaVector<MethodDefinition *> &&overloads)
    {
        overloads_ = std::move(overloads);
    }

    void AddOverload(MethodDefinition *overload)
    {
        overloads_.push_back(overload);
    }

    bool HasOverload(MethodDefinition *overload)
    {
        return std::find(overloads_.begin(), overloads_.end(), overload) != overloads_.end();
    }

    ScriptFunction *Function();
    const ScriptFunction *Function() const;
    PrivateFieldKind ToPrivateFieldKind(bool is_static) const override;
    void CheckMethodModifiers(checker::ETSChecker *checker);
    void CheckExtensionMethod(checker::ETSChecker *checker, ScriptFunction *extension_func);
    void CheckExtensionIsShadowedByMethod(checker::ETSChecker *checker, checker::ETSObjectType *obj_type,
                                          ScriptFunction *extension_func, checker::Signature *sigature);
    void CheckExtensionIsShadowedInCurrentClassOrInterface(checker::ETSChecker *checker,
                                                           checker::ETSObjectType *obj_type,
                                                           ScriptFunction *extension_func,
                                                           checker::Signature *sigature);

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    MethodDefinitionKind kind_;
    ArenaVector<MethodDefinition *> overloads_;
};
}  // namespace panda::es2panda::ir

#endif
