/**
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

#include "varbinder/variableFlags.h"
#include "checker/checker.h"
#include "checker/checkerContext.h"
#include "checker/types/ets/etsObjectType.h"
#include "checker/types/ets/etsTupleType.h"
#include "ir/astNode.h"
#include "lexer/token/tokenType.h"
#include "ir/base/catchClause.h"
#include "ir/expression.h"
#include "ir/typeNode.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/switchCaseStatement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/statements/labelledStatement.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "varbinder/variable.h"
#include "varbinder/scope.h"
#include "varbinder/declaration.h"
#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "util/helpers.h"

namespace ark::es2panda::checker {
void ETSChecker::ValidatePropertyAccess(varbinder::Variable *var, ETSObjectType *obj, const lexer::SourcePosition &pos)
{
    if ((Context().Status() & CheckerStatus::IGNORE_VISIBILITY) != 0U) {
        return;
    }
    if (var->HasFlag(varbinder::VariableFlags::METHOD)) {
        return;
    }

    if (var->HasFlag(varbinder::VariableFlags::PRIVATE) || var->HasFlag(varbinder::VariableFlags::PROTECTED)) {
        if ((Context().ContainingClass() == obj ||
             Context().ContainingClass()->GetOriginalBaseType() == obj->GetOriginalBaseType()) &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        if (var->HasFlag(varbinder::VariableFlags::PROTECTED) && Context().ContainingClass()->IsDescendantOf(obj) &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        auto *currentOutermost = Context().ContainingClass()->OutermostClass();
        auto *objOutermost = obj->OutermostClass();

        if (currentOutermost != nullptr && objOutermost != nullptr && currentOutermost == objOutermost &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        std::ignore = TypeError(var, FormatMsg({"Property ", var->Name(), " is not visible here."}), pos);
    }
}

void ETSChecker::ValidateCallExpressionIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                                  Type *const type)
{
    if (resolved->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE) &&
        ident->Parent()->AsCallExpression()->Callee() != ident) {
        std::ignore =
            TypeError(ident->Variable(),
                      FormatMsg({"Class or interface '", ident->Name(), "' cannot be used as object"}), ident->Start());
    }

    if (ident->Parent()->AsCallExpression()->Callee() != ident) {
        return;
    }
    if (ident->Variable() != nullptr &&  // It should always be true!
        ident->Variable()->Declaration()->Node() != nullptr &&
        ident->Variable()->Declaration()->Node()->IsImportNamespaceSpecifier()) {
        std::ignore =
            TypeError(ident->Variable(), FormatMsg({"Namespace style identifier ", ident->Name(), " is not callable."}),
                      ident->Start());
    }
    if (type->IsETSFunctionType() || type->IsETSDynamicType() ||
        (type->IsETSObjectType() && type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL))) {
        return;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    if (TryTransformingToStaticInvoke(ident, type)) {
        return;
    }

    if (type->IsETSUnionType()) {
        for (auto it : type->AsETSUnionType()->ConstituentTypes()) {
            if (it->IsETSFunctionType() || it->IsETSDynamicType() ||
                (it->IsETSObjectType() && it->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL))) {
                return;
            }
        }
    }

    std::ignore = TypeError(ident->Variable(), FormatMsg({"This expression is not callable."}), ident->Start());
}

void ETSChecker::ValidateNewClassInstanceIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved)
{
    if (ident->Parent()->AsETSNewClassInstanceExpression()->GetTypeRef() == ident && (resolved != nullptr) &&
        !resolved->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE)) {
        LogUnResolvedError(ident);
        return;
    }
}

void ETSChecker::ValidateMemberIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                          Type *const type)
{
    if (resolved->Declaration()->Node()->IsTSEnumDeclaration() &&
        ident->Parent()->AsMemberExpression()->HasMemberKind(ir::MemberExpressionKind::ELEMENT_ACCESS)) {
        return;
    }
    if (ident->Parent()->AsMemberExpression()->IsComputed()) {
        if ((resolved != nullptr) && !resolved->Declaration()->PossibleTDZ()) {
            WrongContextErrorClassifyByType(ident, resolved);
        }

        return;
    }

    if (!IsReferenceType(type) && !type->IsETSEnumType() && !type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        LogUnResolvedError(ident);
        return;
    }
}

void ETSChecker::ValidatePropertyOrDeclaratorIdentifier(ir::Identifier *const ident,
                                                        varbinder::Variable *const resolved)
{
    const auto [target_ident, typeAnnotation] = GetTargetIdentifierAndType(ident);

    if ((resolved != nullptr) && resolved->TsType() != nullptr && resolved->TsType()->IsETSFunctionType()) {
        CheckEtsFunctionType(ident, target_ident);
        return;
    }

    if ((resolved != nullptr) && !resolved->Declaration()->PossibleTDZ()) {
        LogUnResolvedError(ident);
        return;
    }
}

void ETSChecker::ValidateAssignmentIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                              Type *const type)
{
    const auto *const assignmentExpr = ident->Parent()->AsAssignmentExpression();
    if (assignmentExpr->Left() == ident && (resolved != nullptr) && !resolved->Declaration()->PossibleTDZ()) {
        WrongContextErrorClassifyByType(ident, resolved);
        return;
    }

    if (assignmentExpr->Right() == ident && (resolved != nullptr) &&
        (!resolved->Declaration()->PossibleTDZ() && !type->IsETSFunctionType())) {
        WrongContextErrorClassifyByType(ident, resolved);
        return;
    }
}

bool ETSChecker::ValidateBinaryExpressionIdentifier(ir::Identifier *const ident, Type *const type)
{
    const auto *const binaryExpr = ident->Parent()->AsBinaryExpression();
    bool isFinished = false;
    if (binaryExpr->OperatorType() == lexer::TokenType::KEYW_INSTANCEOF && binaryExpr->Right() == ident) {
        if (!IsReferenceType(type)) {
            std::ignore = TypeError(
                ident->Variable(),
                FormatMsg({R"(Using the "instance of" operator with non-object type ")", ident->Name(), "\""}),
                ident->Start());
        }
        isFinished = true;
    }
    return isFinished;
}

void ETSChecker::ValidateResolvedIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved)
{
    if (resolved->Declaration()->IsAnnotationDecl() && !ident->IsAnnotationUsage()) {
        LogTypeError("Annotation missing '@' symbol before annotation name.", ident->Start());
    }

    auto *smartType = Context().GetSmartCast(resolved);
    auto *const resolvedType = GetApparentType(smartType != nullptr ? smartType : GetTypeOfVariable(resolved));

    switch (ident->Parent()->Type()) {
        case ir::AstNodeType::CALL_EXPRESSION: {
            // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
            ValidateCallExpressionIdentifier(ident, resolved, resolvedType);
            break;
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            ValidateNewClassInstanceIdentifier(ident, resolved);
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            ValidateMemberIdentifier(ident, resolved, resolvedType);
            break;
        }
        case ir::AstNodeType::BINARY_EXPRESSION: {
            if (ValidateBinaryExpressionIdentifier(ident, resolvedType)) {
                return;
            }

            [[fallthrough]];
        }
        case ir::AstNodeType::UPDATE_EXPRESSION:
        case ir::AstNodeType::UNARY_EXPRESSION: {
            if (resolved != nullptr && !resolved->Declaration()->PossibleTDZ()) {
                WrongContextErrorClassifyByType(ident, resolved);
            }
            break;
        }
        case ir::AstNodeType::CLASS_PROPERTY:
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            ValidatePropertyOrDeclaratorIdentifier(ident, resolved);
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            ValidateAssignmentIdentifier(ident, resolved, resolvedType);
            break;
        }
        default: {
            if (resolved != nullptr && !resolved->Declaration()->PossibleTDZ() && !resolvedType->IsETSFunctionType()) {
                WrongContextErrorClassifyByType(ident, resolved);
            }
            break;
        }
    }
}

bool ETSChecker::ValidateAnnotationPropertyType(checker::Type *type)
{
    if (type->IsETSArrayType()) {
        return ValidateAnnotationPropertyType(type->AsETSArrayType()->ElementType());
    }

    return MaybePrimitiveBuiltinType(type)->HasTypeFlag(TypeFlag::ETS_NUMERIC | TypeFlag::ETS_BOOLEAN) ||
           type->IsETSStringType() || type->IsETSBooleanType() || type->IsETSEnumType();
}

void ETSChecker::ValidateUnaryOperatorOperand(varbinder::Variable *variable)
{
    if (variable == nullptr || IsVariableGetterSetter(variable) || variable->Declaration() == nullptr) {
        return;
    }

    if (variable->Declaration()->IsConstDecl() || variable->Declaration()->IsReadonlyDecl()) {
        std::string_view fieldType = variable->Declaration()->IsConstDecl() ? "constant" : "readonly";
        if (HasStatus(CheckerStatus::IN_CONSTRUCTOR | CheckerStatus::IN_STATIC_BLOCK) &&
            !variable->HasFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            std::ignore = TypeError(variable, FormatMsg({"Cannot reassign ", fieldType, " ", variable->Name()}),
                                    variable->Declaration()->Node()->Start());
            return;
        }
        if (!HasStatus(CheckerStatus::IN_CONSTRUCTOR | CheckerStatus::IN_STATIC_BLOCK)) {
            std::ignore =
                TypeError(variable, FormatMsg({"Cannot assign to a ", fieldType, " variable ", variable->Name()}),
                          variable->Declaration()->Node()->Start());
        }
    }
}

void ETSChecker::ValidateGenericTypeAliasForClonedNode(ir::TSTypeAliasDeclaration *const typeAliasNode,
                                                       const ir::TSTypeParameterInstantiation *const exactTypeParams)
{
    static std::string_view const TRANSFORMATION_NAME = __func__;

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const clonedNode = typeAliasNode->TypeAnnotation()->Clone(Allocator(), typeAliasNode);

    // Basic check, we really don't want to change the original type nodes, more precise checking should be made
    ASSERT(clonedNode != typeAliasNode->TypeAnnotation());

    // Currently only reference types are checked. This should be extended for other types in a follow up patch, but for
    // complete usability, if the type isn't a simple reference type, then doN't check type alias declaration at all.
    bool checkTypealias = true;

    // Only transforming a temporary cloned node, so no modification is made in the AST
    clonedNode->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [this, &checkTypealias, &exactTypeParams, typeAliasNode](ir::AstNode *const node) -> ir::AstNode * {
            if (!node->IsETSTypeReference()) {
                return node;
            }

            const auto *const nodeIdent = node->AsETSTypeReference()->Part()->Name()->AsIdentifier();

            size_t typeParamIdx = 0;
            for (const auto *const typeParam : typeAliasNode->TypeParams()->Params()) {
                if (typeParam->Name()->AsIdentifier()->Variable() == nodeIdent->Variable()) {
                    break;
                }
                typeParamIdx++;
            }

            if (typeParamIdx == typeAliasNode->TypeParams()->Params().size()) {
                return node;
            }

            auto *const typeParamType = exactTypeParams->Params().at(typeParamIdx);

            if (!typeParamType->IsETSTypeReference()) {
                checkTypealias = false;
                return node;
            }

            return typeParamType->Clone(Allocator(), nullptr);
        },
        TRANSFORMATION_NAME);

    if (checkTypealias) {
        clonedNode->Check(this);
    }
}

bool ETSChecker::ValidateTupleMinElementSize(ir::ArrayExpression *const arrayExpr, ETSTupleType *tuple)
{
    size_t size = 0;
    for (ir::Expression *element : arrayExpr->Elements()) {
        if (element->IsSpreadElement()) {
            Type *argType = element->AsSpreadElement()->Argument()->Check(this);
            if (argType->IsETSTupleType()) {
                size += argType->AsETSTupleType()->GetTupleTypesList().size();
                continue;
            }
            LogTypeError({"'", argType, "' cannot be spread in tuple."}, element->Start());
        }
        ++size;
    }

    if (size < static_cast<size_t>(tuple->GetMinTupleSize())) {
        LogTypeError({"Few elements in array initializer for tuple with size of ",
                      static_cast<size_t>(tuple->GetMinTupleSize())},
                     arrayExpr->Start());
        return false;
    }

    return true;
}
}  // namespace ark::es2panda::checker
