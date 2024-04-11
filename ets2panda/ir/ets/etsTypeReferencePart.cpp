/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "etsTypeReferencePart.h"

#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void ETSTypeReferencePart::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    if (auto *transformedNode = cb(name_); name_ != transformedNode) {
        name_->SetTransformedNode(transformationName, transformedNode);
        name_ = transformedNode->AsExpression();
    }

    if (typeParams_ != nullptr) {
        if (auto *transformedNode = cb(typeParams_); typeParams_ != transformedNode) {
            typeParams_->SetTransformedNode(transformationName, transformedNode);
            typeParams_ = transformedNode->AsTSTypeParameterInstantiation();
        }
    }

    if (prev_ != nullptr) {
        if (auto *transformedNode = cb(prev_); prev_ != transformedNode) {
            prev_->SetTransformedNode(transformationName, transformedNode);
            prev_ = transformedNode->AsETSTypeReferencePart();
        }
    }
}

void ETSTypeReferencePart::Iterate(const NodeTraverser &cb) const
{
    cb(name_);

    if (typeParams_ != nullptr) {
        cb(typeParams_);
    }

    if (prev_ != nullptr) {
        cb(prev_);
    }
}

void ETSTypeReferencePart::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSTypeReferencePart"},
                 {"name", name_},
                 {"typeParams", AstDumper::Optional(typeParams_)},
                 {"previous", AstDumper::Optional(prev_)}});
}

void ETSTypeReferencePart::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(name_ != nullptr);
    name_->Dump(dumper);
    if (typeParams_ != nullptr) {
        typeParams_->Dump(dumper);
    }
}

void ETSTypeReferencePart::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void ETSTypeReferencePart::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ETSTypeReferencePart::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSTypeReferencePart::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSTypeReferencePart::GetType(checker::ETSChecker *checker)
{
    if (prev_ == nullptr) {
        if (name_->IsIdentifier()) {
            const auto ident = name_->AsIdentifier();
            if ((ident->Variable() != nullptr) && (ident->Variable()->Declaration()->IsTypeAliasDecl())) {
                SetTsType(checker->HandleTypeAlias(name_, typeParams_));
            } else if (ident->Name() == compiler::Signatures::UNDEFINED) {
                SetTsType(checker->GlobalETSUndefinedType());
            } else if (ident->Name() == compiler::Signatures::NULL_LITERAL) {
                SetTsType(checker->GlobalETSNullType());
            } else if (ident->Name() == compiler::Signatures::READONLY_TYPE_NAME) {
                SetTsType(checker->HandleReadonlyType(typeParams_));
            } else if (ident->Name() == compiler::Signatures::PARTIAL_TYPE_NAME) {
                // Handle 'Partial<T>' types
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                SetTsType(checker->HandlePartialTypeNode(checker->GetPartialTypeBaseTypeNode(typeParams_)));
            }
        }
        if (TsType() == nullptr) {
            checker::Type *baseType = checker->GetReferencedTypeBase(name_);

            ASSERT(baseType != nullptr);
            if (baseType->IsETSObjectType()) {
                checker::InstantiationContext ctx(checker, baseType->AsETSObjectType(), typeParams_, Start());
                SetTsType(ctx.Result());
            } else {
                SetTsType(baseType);
            }
        }
    } else {
        checker::Type *baseType = prev_->GetType(checker);
        SetTsType(checker->GetReferencedTypeFromBase(baseType, name_));
    }
    return TsType();
}

ETSTypeReferencePart *ETSTypeReferencePart::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const nameClone = name_ != nullptr ? name_->Clone(allocator, nullptr)->AsExpression() : nullptr;
    auto *const typeParamsClone =
        typeParams_ != nullptr ? typeParams_->Clone(allocator, nullptr)->AsTSTypeParameterInstantiation() : nullptr;
    auto *const prevClone = prev_ != nullptr ? prev_->Clone(allocator, nullptr)->AsETSTypeReferencePart() : nullptr;
    if (auto *const clone = allocator->New<ETSTypeReferencePart>(nameClone, typeParamsClone, prevClone);
        clone != nullptr) {
        if (nameClone != nullptr) {
            nameClone->SetParent(clone);
        }

        if (typeParamsClone != nullptr) {
            typeParamsClone->SetParent(clone);
        }

        if (prevClone != nullptr) {
            prevClone->SetParent(clone);
        }

        if (parent != nullptr) {
            clone->SetParent(parent);
        }

        clone->SetRange(Range());
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace ark::es2panda::ir
