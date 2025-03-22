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

#include "memberExpression.h"

#include "checker/TSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/types/ets/etsTupleType.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace ark::es2panda::ir {
MemberExpression::MemberExpression([[maybe_unused]] Tag const tag, MemberExpression const &other,
                                   ArenaAllocator *allocator)
    : MemberExpression(other)
{
    object_ = other.object_ != nullptr ? other.object_->Clone(allocator, this)->AsExpression() : nullptr;
    property_ = other.property_ != nullptr ? other.property_->Clone(allocator, this)->AsExpression() : nullptr;
}

bool MemberExpression::IsPrivateReference() const noexcept
{
    return property_->IsIdentifier() && property_->AsIdentifier()->IsPrivateIdent();
}

void MemberExpression::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    if (auto *transformedNode = cb(object_); object_ != transformedNode) {
        object_->SetTransformedNode(transformationName, transformedNode);
        object_ = transformedNode->AsExpression();
    }

    if (auto *transformedNode = cb(property_); property_ != transformedNode) {
        property_->SetTransformedNode(transformationName, transformedNode);
        property_ = transformedNode->AsExpression();
    }
}

void MemberExpression::Iterate(const NodeTraverser &cb) const
{
    cb(object_);
    cb(property_);
}

void MemberExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "MemberExpression"},
                 {"object", object_},
                 {"property", property_},
                 {"computed", computed_},
                 {"optional", IsOptional()}});
}

void MemberExpression::Dump(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(object_ != nullptr);
    ES2PANDA_ASSERT(property_ != nullptr);

    object_->Dump(dumper);
    if (IsOptional()) {
        dumper->Add("?");
        if ((MemberExpressionKind::ELEMENT_ACCESS & kind_) != 0U) {
            dumper->Add(".");
        }
    }
    if ((MemberExpressionKind::ELEMENT_ACCESS & kind_) != 0U) {
        dumper->Add("[");
        property_->Dump(dumper);
        dumper->Add("]");
    } else {
        dumper->Add(".");
        property_->Dump(dumper);
    }
    if ((parent_ != nullptr) && (parent_->IsBlockStatement() || parent_->IsBlockExpression())) {
        dumper->Add(";");
        dumper->Endl();
    }
}

void MemberExpression::LoadRhs(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    bool isSuper = object_->IsSuperExpression();
    compiler::Operand prop = pg->ToPropertyKey(property_, computed_, isSuper);

    if (isSuper) {
        pg->LoadSuperProperty(this, prop);
    } else if (IsPrivateReference()) {
        const auto &name = property_->AsIdentifier()->Name();
        compiler::VReg objReg = pg->AllocReg();
        pg->StoreAccumulator(this, objReg);
        compiler::VReg ctor = pg->AllocReg();
        compiler::Function::LoadClassContexts(this, pg, ctor, name);
        pg->ClassPrivateFieldGet(this, ctor, objReg, name);
    } else {
        pg->LoadObjProperty(this, prop);
    }
}

void MemberExpression::CompileToRegs(compiler::PandaGen *pg, compiler::VReg object, compiler::VReg property) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, object);

    pg->OptionalChainCheck(IsOptional(), object);

    if (!computed_) {
        pg->LoadAccumulatorString(this, property_->AsIdentifier()->Name());
    } else {
        property_->Compile(pg);
    }

    pg->StoreAccumulator(this, property);
}

void MemberExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void MemberExpression::CompileToReg(compiler::PandaGen *pg, compiler::VReg objReg) const
{
    object_->Compile(pg);
    pg->StoreAccumulator(this, objReg);
    pg->OptionalChainCheck(IsOptional(), objReg);
    LoadRhs(pg);
}

void MemberExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *MemberExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

std::pair<checker::Type *, varbinder::LocalVariable *> MemberExpression::ResolveObjectMember(
    checker::ETSChecker *checker) const
{
    auto resolveRes = checker->ResolveMemberReference(this, objType_);
    switch (resolveRes.size()) {
        case 0U: {
            /* resolution failed, error already reported */
            return {nullptr, nullptr};
        }
        case 1U: {
            if (resolveRes[0]->Kind() == checker::ResolvedKind::PROPERTY) {
                auto var = resolveRes[0]->Variable()->AsLocalVariable();
                checker->ValidatePropertyAccess(var, objType_, property_->Start());
                return {checker->GetTypeOfVariable(var), var};
            }

            if (resolveRes[0]->Kind() == checker::ResolvedKind::EXTENSION_ACCESSOR) {
                auto *callee = const_cast<ir::Expression *>(this->AsExpression());
                callee->AsMemberExpression()->AddMemberKind(ir::MemberExpressionKind::EXTENSION_ACCESSOR);
            }

            return {checker->GetTypeOfVariable(resolveRes[0]->Variable()), nullptr};
        }
        case 2U: {
            auto classMethodType = checker->GetTypeOfVariable(resolveRes[1]->Variable());
            auto extensionMethodType = checker->GetTypeOfVariable(resolveRes[0]->Variable());
            auto *resolvedType = extensionMethodType;
            if (classMethodType->IsETSFunctionType()) {
                ES2PANDA_ASSERT(extensionMethodType->IsETSFunctionType());
                resolvedType = checker->CreateETSExtensionFuncHelperType(classMethodType->AsETSFunctionType(),
                                                                         extensionMethodType->AsETSFunctionType());
            }
            return {resolvedType, nullptr};
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

checker::Type *MemberExpression::TraverseUnionMember(checker::ETSChecker *checker, checker::ETSUnionType *unionType,
                                                     checker::Type *commonPropType)

{
    auto const addPropType = [this, checker, &commonPropType](checker::Type *memberType) {
        if ((memberType != nullptr && memberType->IsETSMethodType()) ||
            (commonPropType != nullptr && !checker->IsTypeIdenticalTo(commonPropType, memberType))) {
            checker->LogError(diagnostic::MEMBER_TYPE_MISMATCH_ACROSS_UNION, {}, Start());
        } else {
            commonPropType = memberType;
        }
    };
    for (auto *const type : unionType->ConstituentTypes()) {
        auto *const apparent = checker->GetApparentType(type);
        if (apparent->IsETSObjectType()) {
            SetObjectType(apparent->AsETSObjectType());
            addPropType(ResolveObjectMember(checker).first);
        } else {
            checker->LogError(diagnostic::UNION_MEMBER_ILLEGAL_TYPE, {unionType}, Start());
        }
    }
    return commonPropType;
}

checker::Type *MemberExpression::CheckUnionMember(checker::ETSChecker *checker, checker::Type *baseType)
{
    auto *const unionType = baseType->AsETSUnionType();
    if (object_->Variable() != nullptr && object_->Variable()->Declaration() != nullptr &&
        object_->Variable()->Declaration()->IsTypeAliasDecl()) {
        checker->LogTypeError("Static union member expression cannot be interpreted.", Start());
        return checker->GlobalTypeError();
    }
    auto *const commonPropType = TraverseUnionMember(checker, unionType, nullptr);
    SetObjectType(checker->GlobalETSObjectType());
    return commonPropType;
}

// Note: extension accessor looks same as member expression in checker phase, but its return type is FunctionType,
// we need to get type of extension accessor in checker. For getter, its type is the return type of the function.
// and for setter, it was a member expression set as left child of an assignment expression, we temporarily set its
// type the same as the right child type. Further work will be done in lowering.
checker::Type *MemberExpression::GetExtensionAccessorReturnType(checker::ETSChecker *checker)
{
    ES2PANDA_ASSERT(checker->IsExtensionETSFunctionType(TsType()));

    bool isExtensionSetter =
        Parent()->IsAssignmentExpression() && (Parent()->AsAssignmentExpression()->Left() == this) &&
        (Parent()->AsAssignmentExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    if (ExtensionAccessorReturnType() != nullptr) {
        return ExtensionAccessorReturnType();
    }
    auto *dummyCallee = this->Clone(checker->Allocator(), nullptr);
    dummyCallee->SetTsType(TsType());
    auto *dummyCallExpr = checker->CreateExtensionAccessorCall(
        checker, dummyCallee, ArenaVector<ir::Expression *>(checker->Allocator()->Adapter()));

    if (dummyCallExpr->Callee()->IsMemberExpression()) {
        dummyCallExpr->Arguments().insert(dummyCallExpr->Arguments().begin(), dummyCallee->Object());
    }

    if (isExtensionSetter) {
        dummyCallExpr->Arguments().emplace_back(Parent()->AsAssignmentExpression()->Right());
    }
    auto *signature = checker->ResolveCallExpressionAndTrailingLambda(TsType()->AsETSFunctionType()->CallSignatures(),
                                                                      dummyCallExpr, Start());
    if (signature == nullptr) {
        checker->LogError(diagnostic::MISSING_EXTENSION_ACCESSOR, {}, Start());
        return checker->GlobalVoidType();
    }

    checker::Type *dummyCallReturnType =
        isExtensionSetter ? Parent()->AsAssignmentExpression()->Right()->TsType() : signature->ReturnType();
    SetExtensionAccessorReturnType(dummyCallReturnType);
    return dummyCallReturnType;
}

checker::Type *MemberExpression::AdjustType(checker::ETSChecker *checker, checker::Type *type)
{
    auto *const objType = checker->GetApparentType(Object()->TsType());
    if (PropVar() != nullptr) {  // access erased property type
        uncheckedType_ = checker->GuaranteedTypeForUncheckedPropertyAccess(PropVar());
    } else if (IsComputed() && objType->IsETSArrayType()) {  // access erased array or tuple type
        uncheckedType_ = checker->GuaranteedTypeForUncheckedCast(objType->AsETSArrayType()->ElementType(), type);
    } else if (IsComputed() && objType->IsETSTupleType()) {
        uncheckedType_ = checker->GuaranteedTypeForUncheckedCast(objType->AsETSTupleType()->GetLubType(), type);
    } else if (checker->IsExtensionAccessorFunctionType(type)) {
        SetTsType(type);
        return GetExtensionAccessorReturnType(checker);
    }
    SetTsType(type == nullptr ? checker->GlobalTypeError() : type);
    return TsType();
}

checker::Type *MemberExpression::SetAndAdjustType(checker::ETSChecker *checker, checker::ETSObjectType *objectType)
{
    SetObjectType(objectType);
    auto [resType, resVar] = ResolveObjectMember(checker);
    if (resType == nullptr) {
        SetTsType(checker->GlobalTypeError());
        return checker->GlobalTypeError();
    }
    SetPropVar(resVar);
    return AdjustType(checker, resType);
}

bool MemberExpression::CheckArrayIndexValue(checker::ETSChecker *checker) const
{
    std::size_t index;

    auto const &number = property_->AsNumberLiteral()->Number();

    if (number.IsInteger()) {
        auto const value = number.GetLong();
        if (value < 0) {
            checker->LogError(diagnostic::NEGATIVE_INDEX, {}, property_->Start());
            return false;
        }
        index = static_cast<std::size_t>(value);
    } else if (number.IsReal()) {
        double value = number.GetDouble();
        double fraction = std::modf(value, &value);
        if (value < 0.0 || fraction >= std::numeric_limits<double>::epsilon()) {
            checker->LogError(diagnostic::INDEX_NEGATIVE_OR_FRACTIONAL, {}, property_->Start());
            return false;
        }
        index = static_cast<std::size_t>(value);
    } else {
        ES2PANDA_UNREACHABLE();
    }

    if (object_->IsArrayExpression() && object_->AsArrayExpression()->Elements().size() <= index) {
        checker->LogError(diagnostic::INDEX_OOB, {}, property_->Start());
        return false;
    }

    return true;
}

checker::Type *MemberExpression::CheckIndexAccessMethod(checker::ETSChecker *checker)
{
    checker::PropertySearchFlags searchFlag = checker::PropertySearchFlags::SEARCH_METHOD;
    searchFlag |= checker::PropertySearchFlags::SEARCH_IN_BASE | checker::PropertySearchFlags::SEARCH_IN_INTERFACES;
    // NOTE(DZ) maybe we need to exclude static methods: search_flag &= ~(checker::PropertySearchFlags::SEARCH_STATIC);

    if (objType_->HasTypeFlag(checker::TypeFlag::GENERIC)) {
        searchFlag |= checker::PropertySearchFlags::SEARCH_ALL;
    }

    bool const isSetter = Parent()->IsAssignmentExpression() && Parent()->AsAssignmentExpression()->Left() == this;
    std::string_view const methodName =
        isSetter ? compiler::Signatures::SET_INDEX_METHOD : compiler::Signatures::GET_INDEX_METHOD;

    auto *const method = objType_->GetProperty(methodName, searchFlag);
    if (method == nullptr || !method->HasFlag(varbinder::VariableFlags::METHOD)) {
        checker->LogError(diagnostic::NO_INDEX_ACCESS_METHOD, {}, Start());
        return nullptr;
    }

    ArenaVector<Expression *> arguments {checker->Allocator()->Adapter()};
    arguments.emplace_back(property_);
    if (isSetter) {
        //  Temporary change the parent of right assignment node to check if correct "$_set" function presents.
        //  later on in lowering the entire assignment expression will be replace top the call to that method.
        auto *value = Parent()->AsAssignmentExpression()->Right();
        value->SetParent(this);
        arguments.emplace_back(value);
    }

    auto &signatures = checker->GetTypeOfVariable(method)->AsETSFunctionType()->CallSignatures();

    checker::Signature *signature = checker->ValidateSignatures(signatures, nullptr, arguments, Start(), "indexing",
                                                                checker::TypeRelationFlag::NO_THROW);
    if (signature == nullptr) {
        checker->LogError(diagnostic::MISSING_INDEX_ACCESSOR_WITH_SIG, {}, Property()->Start());
        return nullptr;
    }
    checker->ValidateSignatureAccessibility(objType_, nullptr, signature, Start(),
                                            {diagnostic::INVISIBLE_INDEX_ACCESSOR, {}});

    ES2PANDA_ASSERT(signature->Function() != nullptr);

    if (signature->Function()->IsThrowing() || signature->Function()->IsRethrowing()) {
        checker->CheckThrowingStatements(this);
    }

    if (isSetter) {
        //  Restore the right assignment node's parent to keep AST invariant valid.
        Parent()->AsAssignmentExpression()->Right()->SetParent(Parent());
        return signature->Params()[1]->TsType();
    }

    return signature->ReturnType();
}

checker::Type *MemberExpression::CheckTupleAccessMethod(checker::ETSChecker *checker, checker::Type *baseType)
{
    ES2PANDA_ASSERT(baseType->IsETSTupleType());
    checker::Type *type = nullptr;
    if (Property()->HasBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOXING_FLAG)) {
        ES2PANDA_ASSERT(Property()->Variable()->Declaration()->Node()->AsClassElement()->Value());
        type = Property()->Variable()->Declaration()->Node()->AsClassElement()->Value()->TsType();
    } else {
        type = Property()->TsType();
    }

    auto idxIfAny = checker->GetTupleElementAccessValue(type);
    if (!idxIfAny.has_value()) {
        return nullptr;
    }
    auto *const tupleTypeAtIdx = baseType->AsETSTupleType()->GetTypeAtIndex(*idxIfAny);

    if ((!Parent()->IsAssignmentExpression() || Parent()->AsAssignmentExpression()->Left() != this) &&
        (!Parent()->IsUpdateExpression())) {
        // Error never should be thrown by this call, because LUB of types can be converted to any type which
        // LUB was calculated by casting
        const checker::CastingContext cast(
            checker->Relation(), {"Tuple type couldn't be converted "},
            checker::CastingContext::ConstructorData {this, baseType->AsETSTupleType()->GetLubType(), tupleTypeAtIdx,
                                                      Start()});
    }

    return tupleTypeAtIdx;
}

checker::Type *MemberExpression::CheckComputed(checker::ETSChecker *checker, checker::Type *baseType)
{
    if (baseType->IsETSDynamicType()) {
        if (!property_->Check(checker)->IsETSStringType()) {
            checker->ValidateArrayIndex(property_);
        }
        return checker->GlobalBuiltinDynamicType(baseType->AsETSDynamicType()->Language());
    }

    if (baseType->IsETSArrayType()) {
        auto *dflt = baseType->AsETSArrayType()->ElementType();
        if (!checker->ValidateArrayIndex(property_)) {
            // error already reported to log
            return dflt;
        }

        // Check if the index value is inside array bounds if it is defined explicitly
        if (property_->IsNumberLiteral() && !CheckArrayIndexValue(checker)) {
            // error reported to log
            return dflt;
        }

        return dflt;
    }

    if (baseType->IsETSTupleType()) {
        auto *dflt = baseType->AsETSTupleType()->GetLubType();
        if (!checker->ValidateTupleIndex(baseType->AsETSTupleType(), this)) {
            // error reported to log
            return dflt;
        }

        // NOTE: apply capture conversion on this type
        auto *res = CheckTupleAccessMethod(checker, baseType);
        return (res == nullptr) ? dflt : res;
    }

    if (baseType->IsETSObjectType()) {
        SetObjectType(baseType->AsETSObjectType());
        return CheckIndexAccessMethod(checker);
    }
    checker->LogError(diagnostic::INDEX_ON_INVALID_TYPE, {}, Object()->Start());
    return nullptr;
}

checker::VerifiedType MemberExpression::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

MemberExpression *MemberExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const clone = allocator->New<MemberExpression>(Tag {}, *this, allocator);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    clone->SetRange(Range());
    return clone;
}

std::string MemberExpression::ToString() const
{
    auto str1 = object_ != nullptr ? object_->ToString() : std::string {INVALID_EXPRESSION};
    if (str1 == INVALID_EXPRESSION) {
        return str1;
    }

    auto str2 = property_ != nullptr ? property_->ToString() : std::string {INVALID_EXPRESSION};

    if (kind_ == MemberExpressionKind::ELEMENT_ACCESS) {
        return str1 + '[' + str2 + ']';
    }

    if (str2 == INVALID_EXPRESSION) {
        return str1 + str2;
    }

    return str1 + '.' + str2;
}
}  // namespace ark::es2panda::ir
