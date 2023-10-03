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

#include "tsQualifiedName.h"

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"

namespace panda::es2panda::ir {
void TSQualifiedName::Iterate(const NodeTraverser &cb) const
{
    cb(left_);
    cb(right_);
}

void TSQualifiedName::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSQualifiedName"}, {"left", left_}, {"right", right_}});
}

void TSQualifiedName::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSQualifiedName::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::Type *base_type = checker->CheckNonNullType(left_->Check(checker), left_->Start());
    binder::Variable *prop = checker->GetPropertyOfType(base_type, right_->Name());

    if (prop != nullptr) {
        return checker->GetTypeOfVariable(prop);
    }

    if (base_type->IsObjectType()) {
        checker::ObjectType *obj_type = base_type->AsObjectType();

        if (obj_type->StringIndexInfo() != nullptr) {
            return obj_type->StringIndexInfo()->GetType();
        }
    }

    checker->ThrowTypeError({"Property ", right_->Name(), " does not exist on this type."}, right_->Start());
    return nullptr;
}

checker::Type *TSQualifiedName::Check(checker::ETSChecker *checker)
{
    checker::Type *base_type = left_->Check(checker);
    if (base_type->IsETSObjectType()) {
        binder::Variable *prop =
            base_type->AsETSObjectType()->GetProperty(right_->Name(), checker::PropertySearchFlags::SEARCH_DECL);

        if (prop != nullptr) {
            return checker->GetTypeOfVariable(prop);
        }
    }

    checker->ThrowTypeError({"'", right_->Name(), "' type does not exist."}, right_->Start());
}

util::StringView TSQualifiedName::ToString(ArenaAllocator *allocator) const
{
    util::UString package_name(allocator);

    const auto *iter = this;

    while (iter->Left()->IsTSQualifiedName()) {
        iter = iter->Left()->AsTSQualifiedName();
    }

    package_name.Append(iter->Left()->AsIdentifier()->Name());

    const ir::AstNode *parent = iter;

    while (parent != nullptr && parent->IsTSQualifiedName()) {
        package_name.Append('.');
        package_name.Append(parent->AsTSQualifiedName()->Right()->AsIdentifier()->Name());
        parent = parent->Parent();
    }

    return package_name.View();
}

util::StringView TSQualifiedName::BaseToString(ArenaAllocator *allocator) const
{
    util::UString package_name(allocator);

    const auto *iter = this;

    while (iter->Left()->IsTSQualifiedName()) {
        iter = iter->Left()->AsTSQualifiedName();
    }

    package_name.Append(iter->Left()->AsIdentifier()->Name());

    const ir::AstNode *parent = iter->Parent();

    while (parent != nullptr && parent->IsTSQualifiedName()) {
        package_name.Append('.');
        package_name.Append(parent->AsTSQualifiedName()->Right()->AsIdentifier()->Name());
        parent = parent->Parent();
    }

    return package_name.View();
}

template <typename T>
static T ResolveLeftMostQualifiedNameImpl(T self)
{
    auto *iter = self;

    while (iter->Left()->IsTSQualifiedName()) {
        iter = iter->Left()->AsTSQualifiedName();
    }

    return iter;
}

ir::TSQualifiedName *TSQualifiedName::ResolveLeftMostQualifiedName()
{
    return ResolveLeftMostQualifiedNameImpl(this);
}

const ir::TSQualifiedName *TSQualifiedName::ResolveLeftMostQualifiedName() const
{
    return ResolveLeftMostQualifiedNameImpl(this);
}
}  // namespace panda::es2panda::ir
