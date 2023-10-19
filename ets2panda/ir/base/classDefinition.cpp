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

#include "classDefinition.h"

#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsClassImplements.h"

namespace panda::es2panda::ir {
const FunctionExpression *ClassDefinition::Ctor() const
{
    return ctor_ != nullptr ? ctor_->Value()->AsFunctionExpression() : nullptr;
}

bool ClassDefinition::HasPrivateMethod() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsMethodDefinition() && element->AsClassElement()->IsPrivateElement();
    });
}

bool ClassDefinition::HasComputedInstanceField() const
{
    return std::any_of(body_.cbegin(), body_.cend(), [](auto *element) {
        return element->IsClassProperty() && element->AsClassElement()->IsComputed() &&
               !(element->AsClassElement()->Modifiers() & ir::ModifierFlags::STATIC);
    });
}

bool ClassDefinition::HasMatchingPrivateKey(const util::StringView &name) const
{
    return std::any_of(body_.cbegin(), body_.cend(), [&name](auto *element) {
        return element->AsClassElement()->IsPrivateElement() && element->AsClassElement()->Id()->Name() == name;
    });
}

void ClassDefinition::TransformChildren(const NodeTransformer &cb)
{
    if (ident_ != nullptr) {
        ident_ = cb(ident_)->AsIdentifier();
    }

    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterDeclaration();
    }

    if (super_class_ != nullptr) {
        super_class_ = cb(super_class_)->AsExpression();
    }

    if (super_type_params_ != nullptr) {
        super_type_params_ = cb(super_type_params_)->AsTSTypeParameterInstantiation();
    }

    for (auto *&it : implements_) {
        it = cb(it)->AsTSClassImplements();
    }

    if (ctor_ != nullptr) {
        ctor_ = cb(ctor_)->AsMethodDefinition();
    }

    for (auto *&it : body_) {
        it = cb(it);
    }
}

void ClassDefinition::Iterate(const NodeTraverser &cb) const
{
    if (ident_ != nullptr) {
        cb(ident_);
    }

    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    if (super_class_ != nullptr) {
        cb(super_class_);
    }

    if (super_type_params_ != nullptr) {
        cb(super_type_params_);
    }

    for (auto *it : implements_) {
        cb(it);
    }

    if (ctor_ != nullptr) {
        cb(ctor_);
    }

    for (auto *it : body_) {
        cb(it);
    }
}

void ClassDefinition::Dump(ir::AstDumper *dumper) const
{
    auto prop_filter = [](AstNode *prop) -> bool {
        return !prop->IsClassStaticBlock() || !prop->AsClassStaticBlock()->Function()->IsHidden();
    };
    dumper->Add({{"id", AstDumper::Nullable(ident_)},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"superClass", AstDumper::Nullable(super_class_)},
                 {"superTypeParameters", AstDumper::Optional(super_type_params_)},
                 {"implements", implements_},
                 {"constructor", AstDumper::Optional(ctor_)},
                 {"body", body_, prop_filter}});
}

void ClassDefinition::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ClassDefinition::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ClassDefinition::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ClassDefinition::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
