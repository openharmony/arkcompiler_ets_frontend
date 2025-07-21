/*
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

#include "etsTypeReferencePart.h"

#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

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
    ES2PANDA_ASSERT(name_ != nullptr);
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

checker::VerifiedType ETSTypeReferencePart::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

static checker::Type *HandleFixedArrayType(checker::ETSChecker *const checker, ETSTypeReferencePart *ref)
{
    auto typeParams = ref->TypeParams();
    if (typeParams == nullptr || typeParams->Params().size() != 1) {
        checker->LogError(diagnostic::FIXED_ARRAY_PARAM_ERROR, {}, ref->Start());
        return checker->GlobalTypeError();
    }
    return checker->CreateETSArrayType(typeParams->Params()[0]->GetType(checker), ref->IsReadonlyType());
}

static checker::Type *HandlePartialType(checker::ETSChecker *const checker, ETSTypeReferencePart *ref)
{
    auto *baseType = checker->HandleUtilityTypeParameterNode(ref->TypeParams(), ref->GetIdent());
    if (baseType != nullptr && baseType->IsETSObjectType() && !baseType->AsETSObjectType()->TypeArguments().empty()) {
        // we treat Partial<A<T,D>> class as a different copy from A<T,D> now,
        // but not a generic type param for Partial<>
        if (ref->TypeParams() != nullptr) {
            for (auto &typeRef : ref->TypeParams()->Params()) {
                checker::InstantiationContext ctx(checker, baseType->AsETSObjectType(),
                                                  typeRef->AsETSTypeReference()->Part()->TypeParams(), ref->Start());
                baseType = ctx.Result();
            }
        }
    }
    return baseType;
}

static checker::Type *CheckPredefinedBuiltinTypes(checker::ETSChecker *const checker, ETSTypeReferencePart *ref)
{
    auto const ident = ref->GetIdent();
    if (ident->Name() == compiler::Signatures::ANY_TYPE_NAME) {
        return checker->GlobalETSAnyType();
    }
    if (ident->Name() == compiler::Signatures::UNDEFINED) {
        return checker->GlobalETSUndefinedType();
    }
    if (ident->Name() == compiler::Signatures::NULL_LITERAL) {
        return checker->GlobalETSNullType();
    }
    if (ident->Name() == compiler::Signatures::NEVER_TYPE_NAME) {
        return checker->GlobalETSNeverType();
    }

    if (ident->Name() == compiler::Signatures::READONLY_TYPE_NAME ||
        ident->Name() == compiler::Signatures::REQUIRED_TYPE_NAME) {
        return checker->HandleUtilityTypeParameterNode(ref->TypeParams(), ident);
    }
    if (ident->Name() == compiler::Signatures::PARTIAL_TYPE_NAME) {
        return HandlePartialType(checker, ref);
    }
    if (ident->Name() == compiler::Signatures::FIXED_ARRAY_TYPE_NAME) {
        return HandleFixedArrayType(checker, ref);
    }
    return nullptr;
}

[[maybe_unused]] static bool CheckTypeAliaLoop(ETSTypeReferencePart *ref, varbinder::Variable *variable)
{
    auto typeAliasDecl = variable->Declaration()->Node()->AsTSTypeAliasDeclaration();
    auto typeDeclaration = typeAliasDecl->TypeParams();
    if (typeDeclaration == nullptr) {
        return false;
    }

    for (auto *param : typeDeclaration->Params()) {
        auto constraint = param->Constraint();
        if (constraint == nullptr || !constraint->IsETSTypeReference()) {
            continue;
        }

        auto part = constraint->AsETSTypeReference()->Part();
        if (part == ref) {
            return true;
        }
    }

    return false;
}

checker::Type *ETSTypeReferencePart::HandleInternalTypes(checker::ETSChecker *const checker)
{
    ES2PANDA_ASSERT(name_->IsIdentifier() || name_->IsTSQualifiedName());

    Identifier *const ident = GetIdent();
    varbinder::Variable *variable = nullptr;

    if (name_->IsIdentifier()) {
        variable = ident->Variable();
    } else {
        if (name_->AsTSQualifiedName()->Left()->Variable() != nullptr &&
            name_->AsTSQualifiedName()->Left()->Variable()->TsType() != nullptr &&
            name_->AsTSQualifiedName()->Left()->Variable()->TsType()->IsETSObjectType()) {
            variable = name_->AsTSQualifiedName()->Left()->Variable()->TsType()->AsETSObjectType()->GetProperty(
                ident->Name(), checker::PropertySearchFlags::SEARCH_DECL);
        }
    }

    if (variable != nullptr && variable->Declaration()->IsTypeAliasDecl()) {
        if (CheckTypeAliaLoop(this, variable)) {
            checker->LogError(diagnostic::CYCLIC_ALIAS, {}, Start());
            return checker->GlobalTypeError();
        }
        return checker->HandleTypeAlias(name_, typeParams_,
                                        variable->Declaration()->AsTypeAliasDecl()->Node()->AsTSTypeAliasDeclaration());
    }

    if (auto res = CheckPredefinedBuiltinTypes(checker, this); res != nullptr) {
        return res;
    }

    if (ident->IsErrorPlaceHolder()) {
        return checker->GlobalTypeError();
    }

    return nullptr;
}

checker::Type *ETSTypeReferencePart::GetType(checker::ETSChecker *checker)
{
    if (TypeParams() != nullptr) {
        for (auto *param : TypeParams()->Params()) {
            checker->CheckAnnotations(param->Annotations());
            if (param->IsETSTypeReference() && param->AsETSTypeReference()->Part()->Name()->IsTSQualifiedName()) {
                param->Check(checker);
            }
        }
    }
    if (prev_ == nullptr) {
        if (name_->IsIdentifier() || name_->IsTSQualifiedName()) {
            SetTsType(HandleInternalTypes(checker));
        }

        if (TsType() == nullptr) {
            checker::Type *baseType = checker->GetReferencedTypeBase(name_);

            ES2PANDA_ASSERT(baseType != nullptr);
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
    auto *const clone = allocator->New<ETSTypeReferencePart>(nameClone, typeParamsClone, prevClone, allocator);

    if (nameClone != nullptr) {
        nameClone->SetParent(clone);
    }

    if (typeParamsClone != nullptr) {
        typeParamsClone->SetParent(clone);
    }

    if (prevClone != nullptr) {
        prevClone->SetParent(clone);
    }

    ES2PANDA_ASSERT(clone);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    clone->SetRange(Range());
    return clone;
}

ir::Identifier *ETSTypeReferencePart::GetIdent()
{
    if (name_->IsTSQualifiedName()) {
        auto ident = name_->AsTSQualifiedName()->Right();
        ES2PANDA_ASSERT(ident->IsIdentifier());
        return ident->AsIdentifier();
    }
    return name_->AsIdentifier();
}

ETSTypeReferencePart *ETSTypeReferencePart::Construct(ArenaAllocator *allocator)
{
    return allocator->New<ETSTypeReferencePart>(nullptr, nullptr, nullptr, allocator);
}

void ETSTypeReferencePart::CopyTo(AstNode *other) const
{
    auto otherImpl = other->AsETSTypeReferencePart();

    otherImpl->name_ = name_;
    otherImpl->typeParams_ = typeParams_;
    otherImpl->prev_ = prev_;

    TypeNode::CopyTo(other);
}

}  // namespace ark::es2panda::ir
