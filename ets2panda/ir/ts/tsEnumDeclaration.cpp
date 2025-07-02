/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "tsEnumDeclaration.h"
#include <cstddef>

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "util/helpers.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "utils/arena_containers.h"

namespace ark::es2panda::ir {
void TSEnumDeclaration::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    for (auto *&it : VectorIterationGuard(decorators_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsDecorator();
        }
    }

    if (auto *transformedNode = cb(key_); key_ != transformedNode) {
        key_->SetTransformedNode(transformationName, transformedNode);
        key_ = transformedNode->AsIdentifier();
    }

    for (auto *&it : VectorIterationGuard(members_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode;
        }
    }
}

void TSEnumDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : VectorIterationGuard(decorators_)) {
        cb(it);
    }

    cb(key_);

    for (auto *it : VectorIterationGuard(members_)) {
        cb(it);
    }
}

void TSEnumDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSEnumDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"id", key_},
                 {"members", members_},
                 {"const", isConst_},
                 {"declare", IsDeclare()}});
}

bool TSEnumDeclaration::RegisterUnexportedForDeclGen(ir::SrcDumper *dumper) const
{
    if (!dumper->IsDeclgen()) {
        return false;
    }

    if (dumper->IsIndirectDepPhase()) {
        return false;
    }

    if (key_->Parent()->IsDefaultExported() || key_->Parent()->IsExported()) {
        return false;
    }

    auto name = key_->AsIdentifier()->Name().Mutf8();
    dumper->AddNode(name, this);
    return true;
}

void TSEnumDeclaration::Dump(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(isConst_ == false);
    ES2PANDA_ASSERT(key_ != nullptr);
    if (RegisterUnexportedForDeclGen(dumper)) {
        return;
    }
    if (key_->Parent()->IsExported() && dumper->IsDeclgen()) {
        dumper->Add("export ");
    } else if (key_->Parent()->IsDefaultExported() && dumper->IsDeclgen()) {
        dumper->Add("export default ");
    }
    if (IsDeclare() || dumper->IsDeclgen()) {
        dumper->Add("declare ");
    }
    dumper->Add("enum ");
    key_->Dump(dumper);
    dumper->Add(" {");
    if (!members_.empty()) {
        dumper->IncrIndent();
        dumper->Endl();
        for (auto member : members_) {
            member->Dump(dumper);
            if (member != members_.back()) {
                dumper->Add(",");
                dumper->Endl();
            }
        }
        dumper->DecrIndent();
        dumper->Endl();
    }
    dumper->Add("}");
    dumper->Endl();
}

// NOTE (csabahurton): this method has not been moved to TSAnalyizer.cpp, because it is not used.
varbinder::EnumMemberResult EvaluateMemberExpression(checker::TSChecker *checker,
                                                     [[maybe_unused]] varbinder::EnumVariable *enumVar,
                                                     ir::MemberExpression *expr)
{
    if (checker::TSChecker::IsConstantMemberAccess(expr->AsExpression())) {
        if (expr->Check(checker)->TypeFlags() == checker::TypeFlag::ENUM) {
            util::StringView name;
            if (!expr->IsComputed()) {
                name = expr->Property()->AsIdentifier()->Name();
            } else {
                ES2PANDA_ASSERT(checker::TSChecker::IsStringLike(expr->Property()));
                name = reinterpret_cast<const ir::StringLiteral *>(expr->Property())->Str();
            }

            // NOTE: aszilagyi.
        }
    }

    return false;
}

void TSEnumDeclaration::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSEnumDeclaration::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSEnumDeclaration::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType TSEnumDeclaration::Check(checker::ETSChecker *const checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

TSEnumDeclaration *TSEnumDeclaration::Construct(ArenaAllocator *allocator)
{
    ArenaVector<AstNode *> members(allocator->Adapter());
    return allocator->New<TSEnumDeclaration>(allocator, nullptr, std::move(members),
                                             ConstructorFlags {false, false, false});
}

void TSEnumDeclaration::CopyTo(AstNode *other) const
{
    auto otherImpl = other->AsTSEnumDeclaration();

    otherImpl->scope_ = scope_;
    otherImpl->decorators_ = decorators_;
    otherImpl->key_ = key_;
    otherImpl->members_ = members_;
    otherImpl->internalName_ = internalName_;
    otherImpl->boxedClass_ = boxedClass_;
    otherImpl->isConst_ = isConst_;

    TypedStatement::CopyTo(other);
}

}  // namespace ark::es2panda::ir
