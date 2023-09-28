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

#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/binaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclarator.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsQualifiedName.h"
#include "plugins/ecmascript/es2panda/ir/base/tsPropertySignature.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeAliasDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeReference.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"

#include "plugins/ecmascript/es2panda/checker/ts/typeElaborationContext.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"

namespace panda::es2panda::checker {
void TSChecker::CheckTruthinessOfType(Type *type, lexer::SourcePosition line_info)
{
    if (type->IsVoidType()) {
        ThrowTypeError("An expression of type void cannot be tested for truthiness", line_info);
    }
}

Type *TSChecker::CheckNonNullType(Type *type, lexer::SourcePosition line_info)
{
    if (type->IsNullType()) {
        ThrowTypeError("Object is possibly 'null'.", line_info);
    }

    if (type->IsUndefinedType()) {
        ThrowTypeError("Object is possibly 'undefined'.", line_info);
    }

    return type;
}

Type *TSChecker::GetBaseTypeOfLiteralType(Type *type)
{
    if (HasStatus(CheckerStatus::KEEP_LITERAL_TYPE)) {
        return type;
    }

    if (type->IsStringLiteralType()) {
        return GlobalStringType();
    }

    if (type->IsNumberLiteralType()) {
        return GlobalNumberType();
    }

    if (type->IsBooleanLiteralType()) {
        return GlobalBooleanType();
    }

    if (type->IsBigintLiteralType()) {
        return GlobalBigintType();
    }

    if (type->IsUnionType()) {
        auto &constituent_types = type->AsUnionType()->ConstituentTypes();
        ArenaVector<Type *> new_constituent_types(Allocator()->Adapter());

        new_constituent_types.reserve(constituent_types.size());
        for (auto *it : constituent_types) {
            new_constituent_types.push_back(GetBaseTypeOfLiteralType(it));
        }

        return CreateUnionType(std::move(new_constituent_types));
    }

    return type;
}

void TSChecker::CheckReferenceExpression(ir::Expression *expr, const char *invalid_reference_msg,
                                         const char *invalid_optional_chain_msg)
{
    if (expr->IsIdentifier()) {
        const util::StringView &name = expr->AsIdentifier()->Name();
        auto result = Scope()->Find(name);
        ASSERT(result.variable);

        if (result.variable->HasFlag(binder::VariableFlags::ENUM_LITERAL)) {
            ThrowTypeError({"Cannot assign to '", name, "' because it is not a variable."}, expr->Start());
        }
    } else if (!expr->IsMemberExpression()) {
        if (expr->IsChainExpression()) {
            ThrowTypeError(invalid_optional_chain_msg, expr->Start());
        }

        ThrowTypeError(invalid_reference_msg, expr->Start());
    }
}

void TSChecker::CheckTestingKnownTruthyCallableOrAwaitableType([[maybe_unused]] ir::Expression *cond_expr,
                                                               [[maybe_unused]] Type *type,
                                                               [[maybe_unused]] ir::AstNode *body)
{
    // TODO(aszilagyi) rework this
}

Type *TSChecker::ExtractDefinitelyFalsyTypes(Type *type)
{
    if (type->IsStringType()) {
        return GlobalEmptyStringType();
    }

    if (type->IsNumberType()) {
        return GlobalZeroType();
    }

    if (type->IsBigintType()) {
        return GlobalZeroBigintType();
    }

    if (type == GlobalFalseType() || type->HasTypeFlag(TypeFlag::NULLABLE) ||
        type->HasTypeFlag(TypeFlag::ANY_OR_UNKNOWN) || type->HasTypeFlag(TypeFlag::VOID) ||
        (type->IsStringLiteralType() && IsTypeIdenticalTo(type, GlobalEmptyStringType())) ||
        (type->IsNumberLiteralType() && IsTypeIdenticalTo(type, GlobalZeroType())) ||
        (type->IsBigintLiteralType() && IsTypeIdenticalTo(type, GlobalZeroBigintType()))) {
        return type;
    }

    if (type->IsUnionType()) {
        auto &constituent_types = type->AsUnionType()->ConstituentTypes();
        ArenaVector<Type *> new_constituent_types(Allocator()->Adapter());

        new_constituent_types.reserve(constituent_types.size());
        for (auto &it : constituent_types) {
            new_constituent_types.push_back(ExtractDefinitelyFalsyTypes(it));
        }

        return CreateUnionType(std::move(new_constituent_types));
    }

    return GlobalNeverType();
}

Type *TSChecker::RemoveDefinitelyFalsyTypes(Type *type)
{
    if ((static_cast<uint64_t>(GetFalsyFlags(type)) & static_cast<uint64_t>(TypeFlag::DEFINITELY_FALSY)) != 0U) {
        if (type->IsUnionType()) {
            auto &constituent_types = type->AsUnionType()->ConstituentTypes();
            ArenaVector<Type *> new_constituent_types(Allocator()->Adapter());

            for (auto &it : constituent_types) {
                if ((static_cast<uint64_t>(GetFalsyFlags(it)) & static_cast<uint64_t>(TypeFlag::DEFINITELY_FALSY)) ==
                    0U) {
                    new_constituent_types.push_back(it);
                }
            }

            if (new_constituent_types.empty()) {
                return GlobalNeverType();
            }

            if (new_constituent_types.size() == 1) {
                return new_constituent_types[0];
            }

            return CreateUnionType(std::move(new_constituent_types));
        }

        return GlobalNeverType();
    }

    return type;
}

TypeFlag TSChecker::GetFalsyFlags(Type *type)
{
    if (type->IsStringLiteralType()) {
        return type->AsStringLiteralType()->Value().Empty() ? TypeFlag::STRING_LITERAL : TypeFlag::NONE;
    }

    if (type->IsNumberLiteralType()) {
        return type->AsNumberLiteralType()->Value() == 0 ? TypeFlag::NUMBER_LITERAL : TypeFlag::NONE;
    }

    if (type->IsBigintLiteralType()) {
        return type->AsBigintLiteralType()->Value() == "0n" ? TypeFlag::BIGINT_LITERAL : TypeFlag::NONE;
    }

    if (type->IsBooleanLiteralType()) {
        return type->AsBooleanLiteralType()->Value() ? TypeFlag::NONE : TypeFlag::BOOLEAN_LITERAL;
    }

    if (type->IsUnionType()) {
        auto &constituent_types = type->AsUnionType()->ConstituentTypes();
        TypeFlag return_flag = TypeFlag::NONE;

        for (auto &it : constituent_types) {
            return_flag |= GetFalsyFlags(it);
        }

        return return_flag;
    }

    return static_cast<TypeFlag>(type->TypeFlags() & TypeFlag::POSSIBLY_FALSY);
}

bool TSChecker::IsVariableUsedInConditionBody(ir::AstNode *parent, binder::Variable *search_var)
{
    bool found = false;

    parent->Iterate([this, search_var, &found](ir::AstNode *child_node) -> void {
        binder::Variable *result_var = nullptr;
        if (child_node->IsIdentifier()) {
            auto result = Scope()->Find(child_node->AsIdentifier()->Name());
            ASSERT(result.variable);
            result_var = result.variable;
        }

        if (search_var == result_var) {
            found = true;
            return;
        }

        if (!child_node->IsMemberExpression()) {
            IsVariableUsedInConditionBody(child_node, search_var);
        }
    });

    return found;
}

bool TSChecker::FindVariableInBinaryExpressionChain(ir::AstNode *parent, binder::Variable *search_var)
{
    bool found = false;

    parent->Iterate([this, search_var, &found](ir::AstNode *child_node) -> void {
        if (child_node->IsIdentifier()) {
            auto result = Scope()->Find(child_node->AsIdentifier()->Name());
            ASSERT(result.variable);
            if (result.variable == search_var) {
                found = true;
                return;
            }
        }

        FindVariableInBinaryExpressionChain(child_node, search_var);
    });

    return found;
}

bool TSChecker::IsVariableUsedInBinaryExpressionChain(ir::AstNode *parent, binder::Variable *search_var)
{
    while (parent->IsBinaryExpression() &&
           parent->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
        if (FindVariableInBinaryExpressionChain(parent, search_var)) {
            return true;
        }

        parent = parent->Parent();
    }

    return false;
}

void TSChecker::ThrowBinaryLikeError(lexer::TokenType op, Type *left_type, Type *right_type,
                                     lexer::SourcePosition line_info)
{
    if (!HasStatus(CheckerStatus::IN_CONST_CONTEXT)) {
        ThrowTypeError({"operator ", op, " cannot be applied to types ", left_type, " and ", AsSrc(right_type)},
                       line_info);
    }

    ThrowTypeError({"operator ", op, " cannot be applied to types ", left_type, " and ", right_type}, line_info);
}

void TSChecker::ThrowAssignmentError(Type *source, Type *target, lexer::SourcePosition line_info,
                                     bool is_as_src_left_type)
{
    if (is_as_src_left_type || !target->HasTypeFlag(TypeFlag::LITERAL)) {
        ThrowTypeError({"Type '", AsSrc(source), "' is not assignable to type '", target, "'."}, line_info);
    }

    ThrowTypeError({"Type '", source, "' is not assignable to type '", target, "'."}, line_info);
}

Type *TSChecker::GetUnaryResultType(Type *operand_type)
{
    if (checker::TSChecker::MaybeTypeOfKind(operand_type, checker::TypeFlag::BIGINT_LIKE)) {
        if (operand_type->HasTypeFlag(checker::TypeFlag::UNION_OR_INTERSECTION) &&
            checker::TSChecker::MaybeTypeOfKind(operand_type, checker::TypeFlag::NUMBER_LIKE)) {
            return GlobalNumberOrBigintType();
        }

        return GlobalBigintType();
    }

    return GlobalNumberType();
}

void TSChecker::ElaborateElementwise(Type *target_type, ir::Expression *source_node, const lexer::SourcePosition &pos)
{
    auto saved_context = SavedCheckerContext(this, CheckerStatus::FORCE_TUPLE | CheckerStatus::KEEP_LITERAL_TYPE);

    Type *source_type = CheckTypeCached(source_node);

    if (IsTypeAssignableTo(source_type, target_type)) {
        return;
    }

    if (target_type->IsArrayType() && source_node->IsArrayExpression()) {
        ArrayElaborationContext(this, target_type, source_type, source_node, pos).Start();
    } else if (target_type->IsObjectType() || target_type->IsUnionType()) {
        if (source_node->IsObjectExpression()) {
            ObjectElaborationContext(this, target_type, source_type, source_node, pos).Start();
        } else if (source_node->IsArrayExpression()) {
            ArrayElaborationContext(this, target_type, source_type, source_node, pos).Start();
        }
    }

    ThrowAssignmentError(source_type, target_type, pos);
}

void TSChecker::InferSimpleVariableDeclaratorType(ir::VariableDeclarator *declarator)
{
    ASSERT(declarator->Id()->IsIdentifier());

    binder::Variable *var = declarator->Id()->AsIdentifier()->Variable();
    ASSERT(var);

    if (declarator->Id()->AsIdentifier()->TypeAnnotation() != nullptr) {
        var->SetTsType(declarator->Id()->AsIdentifier()->TypeAnnotation()->GetType(this));
        return;
    }

    if (declarator->Init() != nullptr) {
        var->SetTsType(CheckTypeCached(declarator->Init()));
        return;
    }

    ThrowTypeError({"Variable ", declarator->Id()->AsIdentifier()->Name(), " implicitly has an any type."},
                   declarator->Id()->Start());
}

Type *TSChecker::GetTypeOfVariable(binder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    binder::Decl *decl = var->Declaration();

    TypeStackElement tse(this, decl->Node(),
                         {"'", var->Name(),
                          "' is referenced directly or indirectly in its "
                          "own initializer ot type annotation."},
                         decl->Node()->Start());

    switch (decl->Type()) {
        case binder::DeclType::CONST:
        case binder::DeclType::LET: {
            if (!decl->Node()->Parent()->IsTSTypeQuery()) {
                ThrowTypeError({"Block-scoped variable '", var->Name(), "' used before its declaration"},
                               decl->Node()->Start());
                break;
            }

            [[fallthrough]];
        }
        case binder::DeclType::VAR: {
            ir::AstNode *declarator =
                util::Helpers::FindAncestorGivenByType(decl->Node(), ir::AstNodeType::VARIABLE_DECLARATOR);
            ASSERT(declarator);

            if (declarator->AsVariableDeclarator()->Id()->IsIdentifier()) {
                InferSimpleVariableDeclaratorType(declarator->AsVariableDeclarator());
                break;
            }

            declarator->Check(this);
            break;
        }
        case binder::DeclType::PROPERTY: {
            var->SetTsType(decl->Node()->AsTSPropertySignature()->TypeAnnotation()->GetType(this));
            break;
        }
        case binder::DeclType::METHOD: {
            auto *signature_info = Allocator()->New<checker::SignatureInfo>(Allocator());
            auto *call_signature = Allocator()->New<checker::Signature>(signature_info, GlobalAnyType());
            var->SetTsType(CreateFunctionTypeWithSignature(call_signature));
            break;
        }
        case binder::DeclType::FUNC: {
            checker::ScopeContext scope_ctx(this, decl->Node()->AsScriptFunction()->Scope());
            InferFunctionDeclarationType(decl->AsFunctionDecl(), var);
            break;
        }
        case binder::DeclType::PARAM: {
            ir::AstNode *declaration = FindAncestorUntilGivenType(decl->Node(), ir::AstNodeType::SCRIPT_FUNCTION);

            if (declaration->IsIdentifier()) {
                auto *ident = declaration->AsIdentifier();
                if (ident->TypeAnnotation() != nullptr) {
                    ASSERT(ident->Variable() == var);
                    var->SetTsType(ident->TypeAnnotation()->GetType(this));
                    break;
                }

                ThrowTypeError({"Parameter ", ident->Name(), " implicitly has an 'any' type."}, ident->Start());
            }

            if (declaration->IsAssignmentPattern() && declaration->AsAssignmentPattern()->Left()->IsIdentifier()) {
                ir::Identifier *ident = declaration->AsAssignmentPattern()->Left()->AsIdentifier();

                if (ident->TypeAnnotation() != nullptr) {
                    ASSERT(ident->Variable() == var);
                    var->SetTsType(ident->TypeAnnotation()->GetType(this));
                    break;
                }

                var->SetTsType(declaration->AsAssignmentPattern()->Right()->Check(this));
            }

            CheckFunctionParameter(declaration->AsExpression(), nullptr);
            break;
        }
        case binder::DeclType::ENUM: {
            ASSERT(var->IsEnumVariable());
            binder::EnumVariable *enum_var = var->AsEnumVariable();

            if (std::holds_alternative<bool>(enum_var->Value())) {
                ThrowTypeError(
                    "A member initializer in a enum declaration cannot reference members declared after it, "
                    "including "
                    "members defined in other enums.",
                    decl->Node()->Start());
            }

            var->SetTsType(std::holds_alternative<double>(enum_var->Value()) ? GlobalNumberType() : GlobalStringType());
            break;
        }
        case binder::DeclType::ENUM_LITERAL: {
            UNREACHABLE();  // TODO(aszilagyi)
        }
        default: {
            break;
        }
    }

    return var->TsType();
}

Type *TSChecker::GetTypeFromClassOrInterfaceReference([[maybe_unused]] ir::TSTypeReference *node, binder::Variable *var)
{
    Type *resolved_type = var->TsType();

    if (resolved_type == nullptr) {
        ObjectDescriptor *desc = Allocator()->New<ObjectDescriptor>(Allocator());
        resolved_type = Allocator()->New<InterfaceType>(Allocator(), var->Name(), desc);
        resolved_type->SetVariable(var);
        var->SetTsType(resolved_type);
    }

    return resolved_type;
}

Type *TSChecker::GetTypeFromTypeAliasReference(ir::TSTypeReference *node, binder::Variable *var)
{
    Type *resolved_type = var->TsType();

    if (resolved_type != nullptr) {
        return resolved_type;
    }

    TypeStackElement tse(this, var, {"Type alias ", var->Name(), " circularly refences itself"}, node->Start());

    ASSERT(var->Declaration()->Node() && var->Declaration()->Node()->IsTSTypeAliasDeclaration());
    ir::TSTypeAliasDeclaration *declaration = var->Declaration()->Node()->AsTSTypeAliasDeclaration();
    resolved_type = declaration->TypeAnnotation()->GetType(this);
    var->SetTsType(resolved_type);

    return resolved_type;
}

Type *TSChecker::GetTypeReferenceType(ir::TSTypeReference *node, binder::Variable *var)
{
    ASSERT(var->Declaration());
    binder::Decl *decl = var->Declaration();

    if (decl->IsInterfaceDecl()) {
        return GetTypeFromClassOrInterfaceReference(node, var);
    }

    if (decl->IsTypeAliasDecl()) {
        return GetTypeFromTypeAliasReference(node, var);
    }

    ThrowTypeError("This reference refers to a value, but is being used as a type here. Did you mean to use 'typeof'?",
                   node->Start());
    return nullptr;
}
}  // namespace panda::es2panda::checker
