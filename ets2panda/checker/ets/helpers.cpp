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

#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "varbinder/variableFlags.h"
#include "checker/checker.h"
#include "checker/checkerContext.h"
#include "checker/ets/narrowingWideningConverter.h"
#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsObjectType.h"
#include "ir/astNode.h"
#include "lexer/token/tokenType.h"
#include "ir/base/catchClause.h"
#include "ir/expression.h"
#include "ir/typeNode.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/switchCaseStatement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/charLiteral.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ts/tsQualifiedName.h"
#include "varbinder/variable.h"
#include "varbinder/scope.h"
#include "varbinder/declaration.h"
#include "parser/ETSparser.h"
#include "parser/program/program.h"
#include "checker/ETSchecker.h"
#include "varbinder/ETSBinder.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/ets/boxingConverter.h"
#include "checker/ets/unboxingConverter.h"
#include "checker/types/ets/types.h"
#include "util/helpers.h"

namespace panda::es2panda::checker {
void ETSChecker::CheckTruthinessOfType(ir::Expression *expr)
{
    checker::Type *type = expr->Check(this);
    auto *unboxed_type = ETSBuiltinTypeAsConditionalType(type);

    if (unboxed_type == GlobalBuiltinVoidType() || unboxed_type->IsETSVoidType()) {
        ThrowTypeError("An expression of type 'void' cannot be tested for truthiness", expr->Start());
    }

    if (unboxed_type != nullptr && !unboxed_type->IsConditionalExprType()) {
        ThrowTypeError("Condition must be of possible condition type", expr->Start());
    }

    if (unboxed_type != nullptr && unboxed_type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        FlagExpressionWithUnboxing(type, unboxed_type, expr);
    }
    expr->SetTsType(unboxed_type);
}

// NOTE: vpukhov. this entire function is isolated work-around until nullish type are not unions
Type *ETSChecker::CreateNullishType(Type *type, checker::TypeFlag nullish_flags, ArenaAllocator *allocator,
                                    TypeRelation *relation, GlobalTypesHolder *global_types)
{
    ASSERT((nullish_flags & ~TypeFlag::NULLISH) == 0);

    auto *const nullish = type->Instantiate(allocator, relation, global_types);

    // Doesnt work for primitive array types, because instantiated type is equal to original one

    if ((nullish_flags & TypeFlag::NULL_TYPE) != 0) {
        nullish->AddTypeFlag(checker::TypeFlag::NULL_TYPE);
    }
    if ((nullish_flags & TypeFlag::UNDEFINED) != 0) {
        nullish->AddTypeFlag(checker::TypeFlag::UNDEFINED);
        if (nullish->IsETSObjectType()) {
            nullish->AsETSObjectType()->SetAssemblerName(GlobalETSObjectType()->AssemblerName());
        }
    }
    ASSERT(!nullish->HasTypeFlag(TypeFlag::ETS_PRIMITIVE));
    return nullish;
}

void ETSChecker::CheckNonNullishType([[maybe_unused]] Type *type, [[maybe_unused]] lexer::SourcePosition line_info)
{
    // NOTE: vpukhov. enable check when type inference is implemented
    (void)type;
}

// NOTE: vpukhov. rewrite with union types
Type *ETSChecker::GetNonNullishType(Type *type) const
{
    if (type->IsETSArrayType()) {
        return type;  // give up
    }

    while (type->IsNullish()) {
        type = type->AsETSObjectType()->GetBaseType();
        ASSERT(type != nullptr);
    }
    return type;
}

// NOTE: vpukhov. rewrite with union types
const Type *ETSChecker::GetNonNullishType(const Type *type) const
{
    if (type->IsETSArrayType()) {
        return type;  // give up
    }

    while (type->IsNullish()) {
        type = type->AsETSObjectType()->GetBaseType();
        ASSERT(type != nullptr);
    }
    return type;
}

Type *ETSChecker::CreateOptionalResultType(Type *type)
{
    if (type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        type = PrimitiveTypeAsETSBuiltinType(type);
        ASSERT(type->IsETSObjectType());
        Relation()->GetNode()->AddBoxingUnboxingFlags(GetBoxingFlag(type));
    }

    return CreateNullishType(type, checker::TypeFlag::UNDEFINED, Allocator(), Relation(), GetGlobalTypesHolder());
}

bool ETSChecker::IsConstantExpression(ir::Expression *expr, Type *type)
{
    return (type->HasTypeFlag(TypeFlag::CONSTANT) && (expr->IsIdentifier() || expr->IsMemberExpression()));
}

Type *ETSChecker::GetNonConstantTypeFromPrimitiveType(Type *type)
{
    if (type->IsETSStringType()) {
        // NOTE: vpukhov. remove when nullish types are unions
        ASSERT(!type->IsNullish());
        return GlobalBuiltinETSStringType();
    }

    if (!type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        return type;
    }

    // NOTE: vpukhov. remove when nullish types are unions
    ASSERT(!type->IsNullish());

    if (type->HasTypeFlag(TypeFlag::LONG)) {
        return GlobalLongType();
    }

    if (type->HasTypeFlag(TypeFlag::BYTE)) {
        return GlobalByteType();
    }

    if (type->HasTypeFlag(TypeFlag::SHORT)) {
        return GlobalShortType();
    }

    if (type->HasTypeFlag(TypeFlag::CHAR)) {
        return GlobalCharType();
    }

    if (type->HasTypeFlag(TypeFlag::INT)) {
        return GlobalIntType();
    }

    if (type->HasTypeFlag(TypeFlag::FLOAT)) {
        return GlobalFloatType();
    }

    if (type->HasTypeFlag(TypeFlag::DOUBLE)) {
        return GlobalDoubleType();
    }

    if (type->IsETSBooleanType()) {
        return GlobalETSBooleanType();
    }
    return type;
}

Type *ETSChecker::GetTypeOfVariable(varbinder::Variable *const var)
{
    if (IsVariableGetterSetter(var)) {
        auto *prop_type = var->TsType()->AsETSFunctionType();
        if (prop_type->HasTypeFlag(checker::TypeFlag::GETTER)) {
            return prop_type->FindGetter()->ReturnType();
        }
        return prop_type->FindSetter()->Params()[0]->TsType();
    }

    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    // NOTE: kbaladurin. forbid usage of imported entities as types without declarations
    if (VarBinder()->AsETSBinder()->IsDynamicModuleVariable(var)) {
        auto *import_data = VarBinder()->AsETSBinder()->DynamicImportDataForVar(var);
        if (import_data->import->IsPureDynamic()) {
            return GlobalBuiltinDynamicType(import_data->import->Language());
        }
    }

    varbinder::Decl *decl = var->Declaration();

    // Before computing the given variables type, we have to make a new checker context frame so that the checking is
    // done in the proper context, and have to enter the scope where the given variable is declared, so reference
    // resolution works properly
    checker::SavedCheckerContext saved_context(this, CheckerStatus::NO_OPTS);
    checker::ScopeContext scope_ctx(this, var->GetScope());
    auto *iter = decl->Node()->Parent();
    while (iter != nullptr) {
        if (iter->IsMethodDefinition()) {
            auto *method_def = iter->AsMethodDefinition();
            ASSERT(method_def->TsType());
            Context().SetContainingSignature(method_def->Function()->Signature());
        }

        if (iter->IsClassDefinition()) {
            auto *class_def = iter->AsClassDefinition();
            ETSObjectType *containing_class {};

            if (class_def->TsType() == nullptr) {
                containing_class = BuildClassProperties(class_def);
            } else {
                containing_class = class_def->TsType()->AsETSObjectType();
            }

            ASSERT(class_def->TsType());
            Context().SetContainingClass(containing_class);
        }

        iter = iter->Parent();
    }

    switch (decl->Type()) {
        case varbinder::DeclType::CLASS: {
            auto *class_def = decl->Node()->AsClassDefinition();
            BuildClassProperties(class_def);
            return class_def->TsType();
        }
        case varbinder::DeclType::ENUM_LITERAL:
        case varbinder::DeclType::CONST:
        case varbinder::DeclType::LET:
        case varbinder::DeclType::VAR: {
            auto *decl_node = decl->Node();

            if (decl->Node()->IsIdentifier()) {
                decl_node = decl_node->Parent();
            }

            return decl_node->Check(this);
        }
        case varbinder::DeclType::FUNC: {
            return decl->Node()->Check(this);
        }
        case varbinder::DeclType::IMPORT: {
            return decl->Node()->Check(this);
        }
        case varbinder::DeclType::TYPE_ALIAS: {
            return GetTypeFromTypeAliasReference(var);
        }
        case varbinder::DeclType::INTERFACE: {
            return BuildInterfaceProperties(decl->Node()->AsTSInterfaceDeclaration());
        }
        default: {
            UNREACHABLE();
        }
    }

    return var->TsType();
}

void ETSChecker::ValidatePropertyAccess(varbinder::Variable *var, ETSObjectType *obj, const lexer::SourcePosition &pos)
{
    if ((Context().Status() & CheckerStatus::IGNORE_VISIBILITY) != 0U) {
        return;
    }
    if (var->HasFlag(varbinder::VariableFlags::METHOD)) {
        return;
    }

    if (var->HasFlag(varbinder::VariableFlags::PRIVATE) || var->HasFlag(varbinder::VariableFlags::PROTECTED)) {
        if (Context().ContainingClass() == obj && obj->IsPropertyInherited(var)) {
            return;
        }

        if (var->HasFlag(varbinder::VariableFlags::PROTECTED) && Context().ContainingClass()->IsDescendantOf(obj) &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        auto *current_outermost = Context().ContainingClass()->OutermostClass();
        auto *obj_outermost = obj->OutermostClass();

        if (current_outermost != nullptr && obj_outermost != nullptr && current_outermost == obj_outermost &&
            obj->IsPropertyInherited(var)) {
            return;
        }

        ThrowTypeError({"Property ", var->Name(), " is not visible here."}, pos);
    }
}

varbinder::Variable *ETSChecker::FindVariableInFunctionScope(const util::StringView name)
{
    return Scope()->FindInFunctionScope(name, varbinder::ResolveBindingOptions::ALL).variable;
}

std::pair<const varbinder::Variable *, const ETSObjectType *> ETSChecker::FindVariableInClassOrEnclosing(
    const util::StringView name, const ETSObjectType *class_type)
{
    const auto search_flags = PropertySearchFlags::SEARCH_ALL | PropertySearchFlags::SEARCH_IN_BASE |
                              PropertySearchFlags::SEARCH_IN_INTERFACES;
    auto *resolved = class_type->GetProperty(name, search_flags);
    while (class_type->EnclosingType() != nullptr && resolved == nullptr) {
        class_type = class_type->EnclosingType();
        resolved = class_type->GetProperty(name, search_flags);
    }

    return {resolved, class_type};
}

varbinder::Variable *ETSChecker::FindVariableInGlobal(const ir::Identifier *const identifier)
{
    return Scope()->FindInGlobal(identifier->Name(), varbinder::ResolveBindingOptions::ALL).variable;
}

bool ETSChecker::IsVariableStatic(const varbinder::Variable *var) const
{
    if (var->HasFlag(varbinder::VariableFlags::METHOD)) {
        return var->TsType()->AsETSFunctionType()->CallSignatures()[0]->HasSignatureFlag(SignatureFlags::STATIC);
    }
    return var->HasFlag(varbinder::VariableFlags::STATIC);
}

bool ETSChecker::IsVariableGetterSetter(const varbinder::Variable *var) const
{
    return var->TsType() != nullptr && var->TsType()->HasTypeFlag(TypeFlag::GETTER_SETTER);
}

void ETSChecker::ThrowError(ir::Identifier *const ident)
{
    ThrowTypeError({"Unresolved reference ", ident->Name()}, ident->Start());
}

void ETSChecker::CheckEtsFunctionType(ir::Identifier *const ident, ir::Identifier const *const id,
                                      ir::TypeNode const *const annotation)
{
    if (annotation == nullptr) {
        ThrowTypeError(
            {"Cannot infer type for ", id->Name(), " because method reference needs an explicit target type"},
            id->Start());
    }

    const auto *const target_type = GetTypeOfVariable(id->Variable());
    ASSERT(target_type != nullptr);

    if (!target_type->IsETSObjectType() || !target_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        ThrowError(ident);
    }
}

void ETSChecker::NotResolvedError(ir::Identifier *const ident)
{
    const auto [class_var, class_type] = FindVariableInClassOrEnclosing(ident->Name(), Context().ContainingClass());
    if (class_var == nullptr) {
        ThrowError(ident);
    }

    if (IsVariableStatic(class_var)) {
        ThrowTypeError(
            {"Static property '", ident->Name(), "' must be accessed through it's class '", class_type->Name(), "'"},
            ident->Start());
    } else {
        ThrowTypeError({"Property '", ident->Name(), "' must be accessed through 'this'"}, ident->Start());
    }
}

void ETSChecker::ValidateCallExpressionIdentifier(ir::Identifier *const ident, Type *const type)
{
    if (ident->Parent()->AsCallExpression()->Callee() == ident && !type->IsETSFunctionType() &&
        !type->IsETSDynamicType() &&
        (!type->IsETSObjectType() || !type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) &&
        !TryTransformingToStaticInvoke(ident, type)) {
        ThrowError(ident);
    }
}

void ETSChecker::ValidateNewClassInstanceIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved)
{
    if (ident->Parent()->AsETSNewClassInstanceExpression()->GetTypeRef() == ident &&
        !resolved->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE)) {
        ThrowError(ident);
    }
}

void ETSChecker::ValidateMemberIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                          Type *const type)
{
    if (ident->Parent()->AsMemberExpression()->IsComputed()) {
        if (!resolved->Declaration()->PossibleTDZ()) {
            ThrowError(ident);
        }

        return;
    }

    if (!type->IsETSObjectType() && !type->IsETSArrayType() && !type->IsETSEnumType() && !type->IsETSStringEnumType() &&
        !type->IsETSUnionType() && !type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        ThrowError(ident);
    }
}

std::pair<const ir::Identifier *, ir::TypeNode *> ETSChecker::GetTargetIdentifierAndType(ir::Identifier *const ident)
{
    if (ident->Parent()->IsClassProperty()) {
        const auto *const class_prop = ident->Parent()->AsClassProperty();
        ASSERT(class_prop->Value() && class_prop->Value() == ident);
        return std::make_pair(class_prop->Key()->AsIdentifier(), class_prop->TypeAnnotation());
    }
    const auto *const variable_decl = ident->Parent()->AsVariableDeclarator();
    ASSERT(variable_decl->Init() && variable_decl->Init() == ident);
    return std::make_pair(variable_decl->Id()->AsIdentifier(), variable_decl->Id()->AsIdentifier()->TypeAnnotation());
}

void ETSChecker::ValidatePropertyOrDeclaratorIdentifier(ir::Identifier *const ident,
                                                        varbinder::Variable *const resolved)
{
    const auto [target_ident, type_annotation] = GetTargetIdentifierAndType(ident);

    if (resolved->TsType()->IsETSFunctionType()) {
        CheckEtsFunctionType(ident, target_ident, type_annotation);
        return;
    }

    if (!resolved->Declaration()->PossibleTDZ()) {
        ThrowError(ident);
    }
}

void ETSChecker::ValidateAssignmentIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved,
                                              Type *const type)
{
    const auto *const assignment_expr = ident->Parent()->AsAssignmentExpression();
    if (assignment_expr->Left() == ident && !resolved->Declaration()->PossibleTDZ()) {
        ThrowError(ident);
    }

    if (assignment_expr->Right() == ident) {
        const auto *const target_type = assignment_expr->Left()->TsType();
        ASSERT(target_type != nullptr);

        if (target_type->IsETSObjectType() &&
            target_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
            if (!type->IsETSFunctionType() &&
                !(type->IsETSObjectType() && type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL))) {
                ThrowError(ident);
            }

            return;
        }

        if (!resolved->Declaration()->PossibleTDZ()) {
            ThrowError(ident);
        }
    }
}

bool ETSChecker::ValidateBinaryExpressionIdentifier(ir::Identifier *const ident, Type *const type)
{
    const auto *const binary_expr = ident->Parent()->AsBinaryExpression();
    bool is_finished = false;
    if (binary_expr->OperatorType() == lexer::TokenType::KEYW_INSTANCEOF && binary_expr->Right() == ident) {
        if (!type->IsETSObjectType()) {
            ThrowError(ident);
        }
        is_finished = true;
    }
    return is_finished;
}

void ETSChecker::ValidateResolvedIdentifier(ir::Identifier *const ident, varbinder::Variable *const resolved)
{
    if (resolved == nullptr) {
        NotResolvedError(ident);
    }

    auto *const resolved_type = GetTypeOfVariable(resolved);

    switch (ident->Parent()->Type()) {
        case ir::AstNodeType::CALL_EXPRESSION: {
            ValidateCallExpressionIdentifier(ident, resolved_type);
            break;
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            ValidateNewClassInstanceIdentifier(ident, resolved);
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            ValidateMemberIdentifier(ident, resolved, resolved_type);
            break;
        }
        case ir::AstNodeType::BINARY_EXPRESSION: {
            if (ValidateBinaryExpressionIdentifier(ident, resolved_type)) {
                return;
            }

            [[fallthrough]];
        }
        case ir::AstNodeType::UPDATE_EXPRESSION:
        case ir::AstNodeType::UNARY_EXPRESSION: {
            if (!resolved->Declaration()->PossibleTDZ()) {
                ThrowError(ident);
            }
            break;
        }
        case ir::AstNodeType::CLASS_PROPERTY:
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            ValidatePropertyOrDeclaratorIdentifier(ident, resolved);
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            ValidateAssignmentIdentifier(ident, resolved, resolved_type);
            break;
        }
        default: {
            if (!resolved->Declaration()->PossibleTDZ() && !resolved_type->IsETSFunctionType()) {
                ThrowError(ident);
            }
            break;
        }
    }
}

void ETSChecker::SaveCapturedVariable(varbinder::Variable *const var, const lexer::SourcePosition &pos)
{
    if (!HasStatus(CheckerStatus::IN_LAMBDA)) {
        return;
    }

    if (var->HasFlag(varbinder::VariableFlags::PROPERTY)) {
        Context().AddCapturedVar(var, pos);
        return;
    }

    if ((!var->HasFlag(varbinder::VariableFlags::LOCAL) && !var->HasFlag(varbinder::VariableFlags::METHOD)) ||
        (var->GetScope()->Node()->IsScriptFunction() && var->GetScope()->Node()->AsScriptFunction()->IsArrow())) {
        return;
    }

    const auto *scope_iter = Scope();
    while (scope_iter != var->GetScope()) {
        if (scope_iter->IsFunctionScope()) {
            Context().AddCapturedVar(var, pos);
            return;
        }
        scope_iter = scope_iter->Parent();
    }
}

Type *ETSChecker::ResolveIdentifier(ir::Identifier *const ident)
{
    if (ident->Variable() != nullptr) {
        auto *const resolved = ident->Variable();
        SaveCapturedVariable(resolved, ident->Start());
        return GetTypeOfVariable(resolved);
    }

    auto *resolved = FindVariableInFunctionScope(ident->Name());
    if (resolved == nullptr) {
        // If the reference is not found already in the current class, then it is not bound to the class, so we have to
        // find the reference in the global class first, then in the global scope
        resolved = FindVariableInGlobal(ident);
    }

    ValidateResolvedIdentifier(ident, resolved);

    if (resolved->HasFlag(varbinder::VariableFlags::METHOD)) {
        ASSERT(resolved->TsType()->IsETSFunctionType() &&
               !resolved->TsType()->AsETSFunctionType()->CallSignatures().empty());
        const auto *const func_type = resolved->TsType()->AsETSFunctionType();
        if (!func_type->CallSignatures().front()->Owner()->HasObjectFlag(checker::ETSObjectFlags::GLOBAL)) {
            // In the case of function references, it is not enough to find the first method field and use it's function
            // type, because at the position of the call we should be able to work with every possible signature, even
            // with ones that came from base classes.
            // NOTE: szd.  find a better way than making a synthetic variable
            resolved = func_type->CallSignatures().front()->Owner()->CreateSyntheticVarFromEverySignature(
                ident->Name(), PropertySearchFlags::SEARCH_METHOD | PropertySearchFlags::SEARCH_IN_BASE);
        }
    }

    ValidatePropertyAccess(resolved, Context().ContainingClass(), ident->Start());
    SaveCapturedVariable(resolved, ident->Start());

    ident->SetVariable(resolved);
    return GetTypeOfVariable(resolved);
}

void ETSChecker::ValidateUnaryOperatorOperand(varbinder::Variable *variable)
{
    if (IsVariableGetterSetter(variable)) {
        return;
    }

    if (variable->Declaration()->IsConstDecl()) {
        if (HasStatus(CheckerStatus::IN_CONSTRUCTOR | CheckerStatus::IN_STATIC_BLOCK) &&
            !variable->HasFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            ThrowTypeError({"Cannot reassign constant field ", variable->Name()},
                           variable->Declaration()->Node()->Start());
        }
        if (!HasStatus(CheckerStatus::IN_CONSTRUCTOR | CheckerStatus::IN_STATIC_BLOCK) &&
            !variable->HasFlag(varbinder::VariableFlags::EXPLICIT_INIT_REQUIRED)) {
            ThrowTypeError({"Cannot assign to a constant variable ", variable->Name()},
                           variable->Declaration()->Node()->Start());
        }
    }
}

std::tuple<Type *, bool> ETSChecker::ApplyBinaryOperatorPromotion(Type *left, Type *right, TypeFlag test,
                                                                  bool do_promotion)
{
    Type *unboxed_l = ETSBuiltinTypeAsPrimitiveType(left);
    Type *unboxed_r = ETSBuiltinTypeAsPrimitiveType(right);
    bool both_const = false;

    if (unboxed_l == nullptr || unboxed_r == nullptr) {
        return {nullptr, false};
    }

    if (!unboxed_l->HasTypeFlag(test) || !unboxed_r->HasTypeFlag(test)) {
        return {nullptr, false};
    }

    if (unboxed_l->HasTypeFlag(TypeFlag::CONSTANT) && unboxed_r->HasTypeFlag(TypeFlag::CONSTANT)) {
        both_const = true;
    }
    if (do_promotion) {
        if (unboxed_l->HasTypeFlag(TypeFlag::ETS_NUMERIC) && unboxed_r->HasTypeFlag(TypeFlag::ETS_NUMERIC)) {
            if (unboxed_l->IsDoubleType() || unboxed_r->IsDoubleType()) {
                return {GlobalDoubleType(), both_const};
            }

            if (unboxed_l->IsFloatType() || unboxed_r->IsFloatType()) {
                return {GlobalFloatType(), both_const};
            }

            if (unboxed_l->IsLongType() || unboxed_r->IsLongType()) {
                return {GlobalLongType(), both_const};
            }

            return {GlobalIntType(), both_const};
        }

        if (IsTypeIdenticalTo(unboxed_l, unboxed_r)) {
            return {unboxed_l, both_const};
        }
    }

    return {unboxed_r, both_const};
}

checker::Type *ETSChecker::ApplyConditionalOperatorPromotion(checker::ETSChecker *checker, checker::Type *unboxed_l,
                                                             checker::Type *unboxed_r)
{
    if ((unboxed_l->HasTypeFlag(checker::TypeFlag::CONSTANT) && unboxed_l->IsIntType()) ||
        (unboxed_r->HasTypeFlag(checker::TypeFlag::CONSTANT) && unboxed_r->IsIntType())) {
        int value = unboxed_l->IsIntType() ? unboxed_l->AsIntType()->GetValue() : unboxed_r->AsIntType()->GetValue();
        checker::Type *other_type = !unboxed_l->IsIntType() ? unboxed_l : unboxed_r;

        switch (checker::ETSChecker::ETSType(other_type)) {
            case checker::TypeFlag::BYTE:
            case checker::TypeFlag::CHAR: {
                if (value <= static_cast<int>(std::numeric_limits<char>::max()) &&
                    value >= static_cast<int>(std::numeric_limits<char>::min())) {
                    return checker->GetNonConstantTypeFromPrimitiveType(other_type);
                }
                break;
            }
            case checker::TypeFlag::SHORT: {
                if (value <= std::numeric_limits<int16_t>::max() && value >= std::numeric_limits<int16_t>::min()) {
                    return checker->GlobalShortType();
                }
                break;
            }
            default: {
                return other_type;
            }
        }
        return checker->GlobalIntType();
    }

    if (unboxed_l->IsDoubleType() || unboxed_r->IsDoubleType()) {
        return checker->GlobalDoubleType();
    }
    if (unboxed_l->IsFloatType() || unboxed_r->IsFloatType()) {
        return checker->GlobalFloatType();
    }
    if (unboxed_l->IsLongType() || unboxed_r->IsLongType()) {
        return checker->GlobalLongType();
    }
    if (unboxed_l->IsIntType() || unboxed_r->IsIntType() || unboxed_l->IsCharType() || unboxed_r->IsCharType()) {
        return checker->GlobalIntType();
    }
    if (unboxed_l->IsShortType() || unboxed_r->IsShortType()) {
        return checker->GlobalShortType();
    }
    if (unboxed_l->IsByteType() || unboxed_r->IsByteType()) {
        return checker->GlobalByteType();
    }

    UNREACHABLE();
}

Type *ETSChecker::ApplyUnaryOperatorPromotion(Type *type, const bool create_const, const bool do_promotion,
                                              const bool is_cond_expr)
{
    Type *unboxed_type = is_cond_expr ? ETSBuiltinTypeAsConditionalType(type) : ETSBuiltinTypeAsPrimitiveType(type);

    if (unboxed_type == nullptr) {
        return nullptr;
    }
    if (do_promotion) {
        switch (ETSType(unboxed_type)) {
            case TypeFlag::BYTE:
            case TypeFlag::SHORT:
            case TypeFlag::CHAR: {
                if (!create_const) {
                    return GlobalIntType();
                }

                return CreateIntTypeFromType(unboxed_type);
            }
            default: {
                break;
            }
        }
    }
    return unboxed_type;
}

bool ETSChecker::IsNullLikeOrVoidExpression(const ir::Expression *expr) const
{
    return expr->TsType()->IsETSNullLike() || expr->TsType()->IsETSVoidType();
}

Type *ETSChecker::HandleBooleanLogicalOperatorsExtended(Type *left_type, Type *right_type, ir::BinaryExpression *expr)
{
    ASSERT(left_type->IsConditionalExprType() && right_type->IsConditionalExprType());

    auto [resolve_left, left_value] =
        IsNullLikeOrVoidExpression(expr->Left()) ? std::make_tuple(true, false) : left_type->ResolveConditionExpr();
    auto [resolve_right, right_value] =
        IsNullLikeOrVoidExpression(expr->Right()) ? std::make_tuple(true, false) : right_type->ResolveConditionExpr();

    if (!resolve_left) {
        if (IsTypeIdenticalTo(left_type, right_type)) {
            return left_type;
        }
        ArenaVector<checker::Type *> types(Allocator()->Adapter());
        types.push_back(left_type);
        types.push_back(right_type);
        return CreateETSUnionType(std::move(types));
    }

    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            if (left_value) {
                expr->SetResult(expr->Left());
                return left_type->IsETSBooleanType() ? CreateETSBooleanType(true) : left_type;
            }

            expr->SetResult(expr->Right());
            return right_type->IsETSBooleanType() && resolve_right ? CreateETSBooleanType(right_value) : right_type;
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            if (left_value) {
                expr->SetResult(expr->Right());
                return right_type->IsETSBooleanType() && resolve_right ? CreateETSBooleanType(right_value) : right_type;
            }

            expr->SetResult(expr->Left());
            return left_type->IsETSBooleanType() ? CreateETSBooleanType(false) : left_type;
        }
        default: {
            break;
        }
    }

    UNREACHABLE();
}

Type *ETSChecker::HandleBooleanLogicalOperators(Type *left_type, Type *right_type, lexer::TokenType token_type)
{
    using UType = typename ETSBooleanType::UType;
    ASSERT(left_type->IsETSBooleanType() && right_type->IsETSBooleanType());

    if (!left_type->HasTypeFlag(checker::TypeFlag::CONSTANT) || !right_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return GlobalETSBooleanType();
    }

    UType left_value = left_type->AsETSBooleanType()->GetValue();
    UType right_value = right_type->AsETSBooleanType()->GetValue();

    switch (token_type) {
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
            return CreateETSBooleanType(left_value ^ right_value);
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
            return CreateETSBooleanType((static_cast<uint8_t>(left_value) & static_cast<uint8_t>(right_value)) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            return CreateETSBooleanType((static_cast<uint8_t>(left_value) | static_cast<uint8_t>(right_value)) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            return CreateETSBooleanType(left_value || right_value);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            return CreateETSBooleanType(left_value && right_value);
        }
        default: {
            break;
        }
    }

    UNREACHABLE();
    return nullptr;
}

void ETSChecker::ResolveReturnStatement(checker::Type *func_return_type, checker::Type *argument_type,
                                        ir::ScriptFunction *containing_func, ir::ReturnStatement *st)
{
    if (func_return_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) ||
        argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        // function return type should be of reference (object) type
        Relation()->SetFlags(checker::TypeRelationFlag::NONE);

        if (!argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            argument_type = PrimitiveTypeAsETSBuiltinType(argument_type);
            if (argument_type == nullptr) {
                ThrowTypeError("Invalid return statement expression", st->Argument()->Start());
            }
            st->Argument()->AddBoxingUnboxingFlags(GetBoxingFlag(argument_type));
        }

        if (!func_return_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
            func_return_type = PrimitiveTypeAsETSBuiltinType(func_return_type);
            if (func_return_type == nullptr) {
                ThrowTypeError("Invalid return function expression", st->Start());
            }
        }

        func_return_type = FindLeastUpperBound(func_return_type, argument_type);
        containing_func->Signature()->SetReturnType(func_return_type);
        containing_func->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
    } else if (func_return_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN) &&
               argument_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN)) {
        // function return type is of primitive type (including enums):
        Relation()->SetFlags(checker::TypeRelationFlag::DIRECT_RETURN |
                             checker::TypeRelationFlag::IN_ASSIGNMENT_CONTEXT |
                             checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
        if (Relation()->IsAssignableTo(func_return_type, argument_type)) {
            func_return_type = argument_type;
            containing_func->Signature()->SetReturnType(func_return_type);
            containing_func->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
        } else if (!Relation()->IsAssignableTo(argument_type, func_return_type)) {
            ThrowTypeError(
                "Return statement type is not compatible with previous method's return statement "
                "type(s).",
                st->Argument()->Start());
        }
    } else {
        ThrowTypeError("Invalid return statement type(s).", st->Start());
    }
}

checker::Type *ETSChecker::CheckArrayElements(ir::Identifier *ident, ir::ArrayExpression *init)
{
    ArenaVector<ir::Expression *> elements = init->AsArrayExpression()->Elements();
    checker::Type *annotation_type = nullptr;
    if (elements.empty()) {
        annotation_type = Allocator()->New<ETSArrayType>(GlobalETSObjectType());
    } else {
        auto type = elements[0]->Check(this);
        auto const prim_type = ETSBuiltinTypeAsPrimitiveType(type);
        for (auto element : elements) {
            auto const e_type = element->Check(this);
            auto const prim_e_type = ETSBuiltinTypeAsPrimitiveType(e_type);
            if (prim_e_type != nullptr && prim_type != nullptr && prim_e_type->HasTypeFlag(TypeFlag::ETS_NUMERIC) &&
                prim_type->HasTypeFlag(TypeFlag::ETS_NUMERIC)) {
                type = GlobalDoubleType();
            } else if (IsTypeIdenticalTo(type, e_type)) {
                continue;
            } else {
                // NOTE: Create union type when implemented here
                ThrowTypeError({"Union type is not implemented yet!"}, ident->Start());
            }
        }
        annotation_type = Allocator()->New<ETSArrayType>(type);
    }
    return annotation_type;
}

checker::Type *ETSChecker::CheckVariableDeclaration(ir::Identifier *ident, ir::TypeNode *type_annotation,
                                                    ir::Expression *init, ir::ModifierFlags flags)
{
    const util::StringView &var_name = ident->Name();
    ASSERT(ident->Variable());
    varbinder::Variable *const binding_var = ident->Variable();
    checker::Type *annotation_type = nullptr;

    const bool is_const = (flags & ir::ModifierFlags::CONST) != 0;

    if (type_annotation != nullptr) {
        annotation_type = GetTypeFromTypeAnnotation(type_annotation);
        binding_var->SetTsType(annotation_type);
    }

    if (init == nullptr) {
        return annotation_type;
    }

    if (type_annotation == nullptr) {
        if (init->IsArrayExpression()) {
            annotation_type = CheckArrayElements(ident, init->AsArrayExpression());
            binding_var->SetTsType(annotation_type);
        }

        if (init->IsObjectExpression()) {
            ThrowTypeError(
                {"Cannot infer type for ", ident->Name(), " because class composite needs an explicit target type"},
                ident->Start());
        }
    }

    if (init->IsMemberExpression() && init->AsMemberExpression()->Object()->IsObjectExpression()) {
        ThrowTypeError({"Class composite must be constructed separately before referring their members."},
                       ident->Start());
    }

    if ((init->IsMemberExpression()) && (annotation_type != nullptr)) {
        SetArrayPreferredTypeForNestedMemberExpressions(init->AsMemberExpression(), annotation_type);
    }

    if (init->IsArrayExpression() && annotation_type->IsETSArrayType()) {
        if (annotation_type->IsETSTupleType()) {
            ValidateTupleMinElementSize(init->AsArrayExpression(), annotation_type->AsETSTupleType());
        }

        init->AsArrayExpression()->SetPreferredType(annotation_type);
    }

    if (init->IsObjectExpression()) {
        init->AsObjectExpression()->SetPreferredType(annotation_type);
    }

    if (type_annotation != nullptr && type_annotation->IsETSFunctionType() && init->IsArrowFunctionExpression()) {
        auto *const arrow_func_expr = init->AsArrowFunctionExpression();
        ir::ScriptFunction *const lambda = arrow_func_expr->Function();
        if (lambda->Params().size() == type_annotation->AsETSFunctionType()->Params().size() &&
            NeedTypeInference(lambda)) {
            InferTypesForLambda(lambda, type_annotation->AsETSFunctionType());
        }
    }
    checker::Type *init_type = init->Check(this);

    if (init_type == nullptr) {
        ThrowTypeError("Cannot get the expression type", init->Start());
    }

    if (type_annotation == nullptr &&
        (init->IsArrowFunctionExpression() ||
         (init->IsTSAsExpression() && init->AsTSAsExpression()->Expr()->IsArrowFunctionExpression()))) {
        if (init->IsArrowFunctionExpression()) {
            type_annotation = init->AsArrowFunctionExpression()->CreateTypeAnnotation(this);
        } else {
            type_annotation = init->AsTSAsExpression()->TypeAnnotation();
        }
        ident->SetTsTypeAnnotation(type_annotation);
        type_annotation->SetParent(ident);
        annotation_type = GetTypeFromTypeAnnotation(type_annotation);
        binding_var->SetTsType(annotation_type);
    }

    if (annotation_type != nullptr) {
        AssignmentContext(Relation(), init, init_type, annotation_type, init->Start(),
                          {"Initializers type is not assignable to the target type"});
        if (is_const && init_type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) &&
            annotation_type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
            binding_var->SetTsType(init->TsType());
        }
        return binding_var->TsType();
    }

    if (init_type->IsETSNullLike()) {
        TypeFlag nullish_flags {0};

        if (init_type->IsETSNullType()) {
            nullish_flags = TypeFlag::NULL_TYPE;
        }
        if (init_type->IsETSUndefinedType()) {
            nullish_flags = TypeFlag::UNDEFINED;
        }
        init_type = CreateNullishType(GetGlobalTypesHolder()->GlobalETSObjectType(), nullish_flags, Allocator(),
                                      Relation(), GetGlobalTypesHolder());
    }

    if (init_type->IsETSObjectType() && init_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::ENUM) &&
        !init->IsMemberExpression()) {
        ThrowTypeError({"Cannot assign type '", init_type->AsETSObjectType()->Name(), "' for variable ", var_name, "."},
                       init->Start());
    }

    if (init_type->IsNullish() || is_const) {
        binding_var->SetTsType(init_type);
    } else {
        binding_var->SetTsType(GetNonConstantTypeFromPrimitiveType(init_type));
    }

    return binding_var->TsType();
}

void ETSChecker::SetArrayPreferredTypeForNestedMemberExpressions(ir::MemberExpression *expr, Type *annotation_type)
{
    if ((expr == nullptr) || (annotation_type == nullptr)) {
        return;
    }

    if (expr->Kind() != ir::MemberExpressionKind::ELEMENT_ACCESS) {
        return;
    }

    // Expand all member expressions
    Type *element_type = annotation_type;
    ir::Expression *object = expr->Object();
    while ((object != nullptr) && (object->IsMemberExpression())) {
        ir::MemberExpression *member_expr = object->AsMemberExpression();
        if (member_expr->Kind() != ir::MemberExpressionKind::ELEMENT_ACCESS) {
            return;
        }

        object = member_expr->Object();
        element_type = CreateETSArrayType(element_type);
    }

    // Set explicit target type for array
    if ((object != nullptr) && (object->IsArrayExpression())) {
        ir::ArrayExpression *array = object->AsArrayExpression();
        array->SetPreferredType(CreateETSArrayType(element_type));
    }
}

Type *ETSChecker::GetTypeFromTypeAliasReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *const alias_type_node = var->Declaration()->Node()->AsTSTypeAliasDeclaration();
    TypeStackElement tse(this, alias_type_node, "Circular type alias reference", alias_type_node->Start());
    auto *const aliased_type = GetTypeFromTypeAnnotation(alias_type_node->TypeAnnotation());

    var->SetTsType(aliased_type);
    return aliased_type;
}

Type *ETSChecker::GetTypeFromInterfaceReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *interface_type = BuildInterfaceProperties(var->Declaration()->Node()->AsTSInterfaceDeclaration());
    var->SetTsType(interface_type);
    return interface_type;
}

Type *ETSChecker::GetTypeFromClassReference(varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto *class_type = BuildClassProperties(var->Declaration()->Node()->AsClassDefinition());
    var->SetTsType(class_type);
    return class_type;
}

Type *ETSChecker::GetTypeFromEnumReference([[maybe_unused]] varbinder::Variable *var)
{
    if (var->TsType() != nullptr) {
        return var->TsType();
    }

    auto const *const enum_decl = var->Declaration()->Node()->AsTSEnumDeclaration();
    if (auto *const item_init = enum_decl->Members().front()->AsTSEnumMember()->Init(); item_init->IsNumberLiteral()) {
        return CreateETSEnumType(enum_decl);
    } else if (item_init->IsStringLiteral()) {  // NOLINT(readability-else-after-return)
        return CreateETSStringEnumType(enum_decl);
    } else {  // NOLINT(readability-else-after-return)
        ThrowTypeError("Invalid enumeration value type.", enum_decl->Start());
    }
}

Type *ETSChecker::GetTypeFromTypeParameterReference(varbinder::LocalVariable *var, const lexer::SourcePosition &pos)
{
    ASSERT(var->Declaration()->Node()->IsTSTypeParameter());
    if ((var->Declaration()->Node()->AsTSTypeParameter()->Parent()->Parent()->IsClassDefinition() ||
         var->Declaration()->Node()->AsTSTypeParameter()->Parent()->Parent()->IsTSInterfaceDeclaration()) &&
        HasStatus(CheckerStatus::IN_STATIC_CONTEXT)) {
        ThrowTypeError({"Cannot make a static reference to the non-static type ", var->Name()}, pos);
    }

    return var->TsType();
}

std::vector<util::StringView> ETSChecker::GetNameForSynteticObjectType(const util::StringView &source)
{
    const std::string str = source.Mutf8();
    std::istringstream ss {str};
    const char delimiter = '.';
    std::string token;

    std::vector<util::StringView> synthetic_name {};

    while (std::getline(ss, token, delimiter)) {
        if (!token.empty()) {
            util::UString s_v(token, Allocator());
            synthetic_name.emplace_back(s_v.View());
        }
    }

    return synthetic_name;
}

void ETSChecker::SetPropertiesForModuleObject(checker::ETSObjectType *module_obj_type,
                                              const util::StringView &import_path)
{
    auto *ets_binder = static_cast<varbinder::ETSBinder *>(VarBinder());

    auto ext_records = ets_binder->GetGlobalRecordTable()->Program()->ExternalSources();
    auto res = [ets_binder, ext_records, import_path]() {
        auto r = ext_records.find(import_path);
        return r != ext_records.end() ? r : ext_records.find(ets_binder->GetResolvedImportPath(import_path));
    }();
    for (auto [_, var] : res->second.front()->GlobalClassScope()->StaticFieldScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            module_obj_type->AddProperty<checker::PropertyType::STATIC_FIELD>(var->AsLocalVariable());
        }
    }

    for (auto [_, var] : res->second.front()->GlobalClassScope()->StaticMethodScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            module_obj_type->AddProperty<checker::PropertyType::STATIC_METHOD>(var->AsLocalVariable());
        }
    }

    for (auto [_, var] : res->second.front()->GlobalClassScope()->InstanceDeclScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            module_obj_type->AddProperty<checker::PropertyType::STATIC_DECL>(var->AsLocalVariable());
        }
    }

    for (auto [_, var] : res->second.front()->GlobalClassScope()->TypeAliasScope()->Bindings()) {
        (void)_;
        if (var->AsLocalVariable()->Declaration()->Node()->IsExported()) {
            module_obj_type->AddProperty<checker::PropertyType::STATIC_DECL>(var->AsLocalVariable());
        }
    }
}

void ETSChecker::SetrModuleObjectTsType(ir::Identifier *local, checker::ETSObjectType *module_obj_type)
{
    auto *ets_binder = static_cast<varbinder::ETSBinder *>(VarBinder());

    for (auto [bindingName, var] : ets_binder->TopScope()->Bindings()) {
        if (bindingName.Is(local->Name().Mutf8())) {
            var->SetTsType(module_obj_type);
        }
    }
}

Type *ETSChecker::GetReferencedTypeFromBase([[maybe_unused]] Type *base_type, [[maybe_unused]] ir::Expression *name)
{
    return nullptr;
}

Type *ETSChecker::GetReferencedTypeBase(ir::Expression *name)
{
    if (name->IsTSQualifiedName()) {
        auto *qualified = name->AsTSQualifiedName();
        return qualified->Check(this);
    }

    ASSERT(name->IsIdentifier() && name->AsIdentifier()->Variable() != nullptr);

    // NOTE: kbaladurin. forbid usage imported entities as types without declarations
    auto *import_data = VarBinder()->AsETSBinder()->DynamicImportDataForVar(name->AsIdentifier()->Variable());
    if (import_data != nullptr && import_data->import->IsPureDynamic()) {
        return GlobalBuiltinDynamicType(import_data->import->Language());
    }

    auto *ref_var = name->AsIdentifier()->Variable()->AsLocalVariable();

    switch (ref_var->Declaration()->Node()->Type()) {
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            return GetTypeFromInterfaceReference(ref_var);
        }
        case ir::AstNodeType::CLASS_DECLARATION:
        case ir::AstNodeType::STRUCT_DECLARATION:
        case ir::AstNodeType::CLASS_DEFINITION: {
            return GetTypeFromClassReference(ref_var);
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            return GetTypeFromEnumReference(ref_var);
        }
        case ir::AstNodeType::TS_TYPE_PARAMETER: {
            return GetTypeFromTypeParameterReference(ref_var, name->Start());
        }
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION: {
            return GetTypeFromTypeAliasReference(ref_var);
        }
        default: {
            UNREACHABLE();
        }
    }
}

void ETSChecker::ConcatConstantString(util::UString &target, Type *type)
{
    switch (ETSType(type)) {
        case TypeFlag::ETS_OBJECT: {
            ASSERT(type->IsETSStringType());
            target.Append(type->AsETSStringType()->GetValue());
            break;
        }
        case TypeFlag::ETS_BOOLEAN: {
            ETSBooleanType::UType value = type->AsETSBooleanType()->GetValue();
            target.Append(value ? "true" : "false");
            break;
        }
        case TypeFlag::BYTE: {
            ByteType::UType value = type->AsByteType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::CHAR: {
            CharType::UType value = type->AsCharType()->GetValue();
            std::string s(1, value);
            target.Append(s);
            break;
        }
        case TypeFlag::SHORT: {
            ShortType::UType value = type->AsShortType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::INT: {
            IntType::UType value = type->AsIntType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::LONG: {
            LongType::UType value = type->AsLongType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::FLOAT: {
            FloatType::UType value = type->AsFloatType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        case TypeFlag::DOUBLE: {
            DoubleType::UType value = type->AsDoubleType()->GetValue();
            target.Append(std::to_string(value));
            break;
        }
        default: {
            UNREACHABLE();
        }
    }
}

Type *ETSChecker::HandleStringConcatenation(Type *left_type, Type *right_type)
{
    ASSERT(left_type->IsETSStringType() || right_type->IsETSStringType());

    if (!left_type->HasTypeFlag(checker::TypeFlag::CONSTANT) || !right_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        return GlobalETSStringLiteralType();
    }

    util::UString concatenated(Allocator());
    ConcatConstantString(concatenated, left_type);
    ConcatConstantString(concatenated, right_type);

    return CreateETSStringLiteralType(concatenated.View());
}

ETSFunctionType *ETSChecker::FindFunctionInVectorGivenByName(util::StringView name,
                                                             ArenaVector<ETSFunctionType *> &list)
{
    for (auto *it : list) {
        if (it->Name() == name) {
            return it;
        }
    }

    return nullptr;
}

bool ETSChecker::IsFunctionContainsSignature(ETSFunctionType *func_type, Signature *signature)
{
    for (auto *it : func_type->CallSignatures()) {
        Relation()->IsIdenticalTo(it, signature);
        if (Relation()->IsTrue()) {
            return true;
        }
    }

    return false;
}

void ETSChecker::CheckFunctionContainsClashingSignature(const ETSFunctionType *func_type, Signature *signature)
{
    for (auto *it : func_type->CallSignatures()) {
        SavedTypeRelationFlagsContext strf_ctx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);
        Relation()->IsIdenticalTo(it, signature);
        if (Relation()->IsTrue() && it->Function()->Id()->Name() == signature->Function()->Id()->Name()) {
            std::stringstream ss;
            it->ToString(ss, nullptr, true);
            auto sig_str1 = ss.str();
            ss.str(std::string {});  // Clear buffer
            signature->ToString(ss, nullptr, true);
            auto sig_str2 = ss.str();
            ThrowTypeError({"Function '", it->Function()->Id()->Name(), sig_str1.c_str(),
                            "' is redeclared with different signature '", signature->Function()->Id()->Name(),
                            sig_str2.c_str(), "'"},
                           signature->Function()->ReturnTypeAnnotation()->Start());
        }
    }
}

void ETSChecker::MergeSignatures(ETSFunctionType *target, ETSFunctionType *source)
{
    for (auto *s : source->CallSignatures()) {
        if (IsFunctionContainsSignature(target, s)) {
            continue;
        }

        CheckFunctionContainsClashingSignature(target, s);
        target->AddCallSignature(s);
    }
}

void ETSChecker::MergeComputedAbstracts(ArenaVector<ETSFunctionType *> &merged, ArenaVector<ETSFunctionType *> &current)
{
    for (auto *curr : current) {
        auto name = curr->Name();
        auto *found = FindFunctionInVectorGivenByName(name, merged);
        if (found != nullptr) {
            MergeSignatures(found, curr);
            continue;
        }

        merged.push_back(curr);
    }
}

ir::AstNode *ETSChecker::FindAncestorGivenByType(ir::AstNode *node, ir::AstNodeType type, const ir::AstNode *end_node)
{
    auto *iter = node->Parent();

    while (iter != end_node) {
        if (iter->Type() == type) {
            return iter;
        }

        iter = iter->Parent();
    }

    return nullptr;
}

util::StringView ETSChecker::GetContainingObjectNameFromSignature(Signature *signature)
{
    ASSERT(signature->Function());
    auto *iter = signature->Function()->Parent();

    while (iter != nullptr) {
        if (iter->IsClassDefinition()) {
            return iter->AsClassDefinition()->Ident()->Name();
        }

        if (iter->IsTSInterfaceDeclaration()) {
            return iter->AsTSInterfaceDeclaration()->Id()->Name();
        }

        iter = iter->Parent();
    }

    UNREACHABLE();
    return {""};
}

bool ETSChecker::IsTypeBuiltinType(const Type *type) const
{
    if (!type->IsETSObjectType()) {
        return false;
    }

    switch (type->AsETSObjectType()->BuiltInKind()) {
        case ETSObjectFlags::BUILTIN_BOOLEAN:
        case ETSObjectFlags::BUILTIN_BYTE:
        case ETSObjectFlags::BUILTIN_SHORT:
        case ETSObjectFlags::BUILTIN_CHAR:
        case ETSObjectFlags::BUILTIN_INT:
        case ETSObjectFlags::BUILTIN_LONG:
        case ETSObjectFlags::BUILTIN_FLOAT:
        case ETSObjectFlags::BUILTIN_DOUBLE: {
            return true;
        }
        default:
            return false;
    }
}

bool ETSChecker::IsReferenceType(const Type *type)
{
    return type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) || type->IsETSNullLike() ||
           type->IsETSStringType();
}

const ir::AstNode *ETSChecker::FindJumpTarget(ir::AstNodeType node_type, const ir::AstNode *node,
                                              const ir::Identifier *target)
{
    const auto *iter = node->Parent();

    while (iter != nullptr) {
        switch (iter->Type()) {
            case ir::AstNodeType::LABELLED_STATEMENT: {
                if (const auto *labelled = iter->AsLabelledStatement(); labelled->Ident()->Name() == target->Name()) {
                    return node_type == ir::AstNodeType::CONTINUE_STATEMENT ? labelled->GetReferencedStatement()
                                                                            : labelled;
                }
                break;
            }
            case ir::AstNodeType::DO_WHILE_STATEMENT:
            case ir::AstNodeType::WHILE_STATEMENT:
            case ir::AstNodeType::FOR_UPDATE_STATEMENT:
            case ir::AstNodeType::FOR_OF_STATEMENT:
            case ir::AstNodeType::SWITCH_STATEMENT: {
                if (target == nullptr) {
                    return iter;
                }
                break;
            }
            default: {
                break;
            }
        }

        iter = iter->Parent();
    }

    UNREACHABLE();
    return nullptr;
}

varbinder::VariableFlags ETSChecker::GetAccessFlagFromNode(const ir::AstNode *node)
{
    if (node->IsPrivate()) {
        return varbinder::VariableFlags::PRIVATE;
    }

    if (node->IsProtected()) {
        return varbinder::VariableFlags::PROTECTED;
    }

    return varbinder::VariableFlags::PUBLIC;
}

void ETSChecker::CheckSwitchDiscriminant(ir::Expression *discriminant)
{
    ASSERT(discriminant->TsType());

    auto discriminant_type = discriminant->TsType();
    if (discriminant_type->HasTypeFlag(TypeFlag::VALID_SWITCH_TYPE)) {
        return;
    }

    if (discriminant_type->IsETSObjectType() &&
        discriminant_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::VALID_SWITCH_TYPE)) {
        if (discriminant_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
            discriminant->SetBoxingUnboxingFlags(GetUnboxingFlag(ETSBuiltinTypeAsPrimitiveType(discriminant_type)));
        }
        return;
    }

    ThrowTypeError({"Incompatible types. Found: ", discriminant_type,
                    ", required: char , byte , short , int, long , Char , Byte , Short , Int, Long , String "
                    "or an enum type"},
                   discriminant->Start());
}

Type *ETSChecker::ETSBuiltinTypeAsPrimitiveType(Type *object_type)
{
    if (object_type == nullptr) {
        return nullptr;
    }

    if (object_type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) || object_type->HasTypeFlag(TypeFlag::ETS_ENUM) ||
        object_type->HasTypeFlag(TypeFlag::ETS_STRING_ENUM)) {
        return object_type;
    }

    if (!object_type->IsETSObjectType() ||
        !object_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
        return nullptr;
    }

    auto saved_result = Relation()->IsTrue();
    Relation()->Result(false);

    UnboxingConverter converter = UnboxingConverter(AsETSChecker(), Relation(), object_type, object_type);
    Relation()->Result(saved_result);
    return converter.Result();
}

Type *ETSChecker::ETSBuiltinTypeAsConditionalType(Type *object_type)
{
    if ((object_type == nullptr) || !object_type->IsConditionalExprType()) {
        return nullptr;
    }

    return object_type;
}

Type *ETSChecker::PrimitiveTypeAsETSBuiltinType(Type *object_type)
{
    if (object_type == nullptr) {
        return nullptr;
    }

    if (object_type->IsETSObjectType() &&
        object_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNBOXABLE_TYPE)) {
        return object_type;
    }

    if (!object_type->HasTypeFlag(TypeFlag::ETS_PRIMITIVE) || object_type->IsETSVoidType()) {
        return nullptr;
    }

    auto saved_result = Relation()->IsTrue();
    Relation()->Result(false);

    BoxingConverter converter = BoxingConverter(AsETSChecker(), Relation(), object_type,
                                                Checker::GetGlobalTypesHolder()->GlobalIntegerBuiltinType());
    Relation()->Result(saved_result);
    return converter.Result();
}

void ETSChecker::AddBoxingUnboxingFlagsToNode(ir::AstNode *node, Type *boxing_unboxing_type)
{
    if (boxing_unboxing_type->IsETSObjectType()) {
        node->AddBoxingUnboxingFlags(GetBoxingFlag(boxing_unboxing_type));
    } else {
        node->AddBoxingUnboxingFlags(GetUnboxingFlag(boxing_unboxing_type));
    }
}

ir::BoxingUnboxingFlags ETSChecker::GetBoxingFlag(Type *const boxing_type)
{
    auto type_kind = TypeKind(ETSBuiltinTypeAsPrimitiveType(boxing_type));
    switch (type_kind) {
        case TypeFlag::ETS_BOOLEAN: {
            return ir::BoxingUnboxingFlags::BOX_TO_BOOLEAN;
        }
        case TypeFlag::BYTE: {
            return ir::BoxingUnboxingFlags::BOX_TO_BYTE;
        }
        case TypeFlag::CHAR: {
            return ir::BoxingUnboxingFlags::BOX_TO_CHAR;
        }
        case TypeFlag::SHORT: {
            return ir::BoxingUnboxingFlags::BOX_TO_SHORT;
        }
        case TypeFlag::INT: {
            return ir::BoxingUnboxingFlags::BOX_TO_INT;
        }
        case TypeFlag::LONG: {
            return ir::BoxingUnboxingFlags::BOX_TO_LONG;
        }
        case TypeFlag::FLOAT: {
            return ir::BoxingUnboxingFlags::BOX_TO_FLOAT;
        }
        case TypeFlag::DOUBLE: {
            return ir::BoxingUnboxingFlags::BOX_TO_DOUBLE;
        }
        default:
            UNREACHABLE();
    }
}

ir::BoxingUnboxingFlags ETSChecker::GetUnboxingFlag(Type const *const unboxing_type) const
{
    auto type_kind = TypeKind(unboxing_type);
    switch (type_kind) {
        case TypeFlag::ETS_BOOLEAN: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_BOOLEAN;
        }
        case TypeFlag::BYTE: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_BYTE;
        }
        case TypeFlag::CHAR: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_CHAR;
        }
        case TypeFlag::SHORT: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_SHORT;
        }
        case TypeFlag::INT: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_INT;
        }
        case TypeFlag::LONG: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_LONG;
        }
        case TypeFlag::FLOAT: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_FLOAT;
        }
        case TypeFlag::DOUBLE: {
            return ir::BoxingUnboxingFlags::UNBOX_TO_DOUBLE;
        }
        default:
            UNREACHABLE();
    }
}

Type *ETSChecker::MaybeBoxedType(const varbinder::Variable *var, ArenaAllocator *allocator) const
{
    auto *var_type = var->TsType();
    if (var->HasFlag(varbinder::VariableFlags::BOXED)) {
        switch (TypeKind(var_type)) {
            case TypeFlag::ETS_BOOLEAN:
                return GetGlobalTypesHolder()->GlobalBooleanBoxBuiltinType();
            case TypeFlag::BYTE:
                return GetGlobalTypesHolder()->GlobalByteBoxBuiltinType();
            case TypeFlag::CHAR:
                return GetGlobalTypesHolder()->GlobalCharBoxBuiltinType();
            case TypeFlag::SHORT:
                return GetGlobalTypesHolder()->GlobalShortBoxBuiltinType();
            case TypeFlag::INT:
                return GetGlobalTypesHolder()->GlobalIntBoxBuiltinType();
            case TypeFlag::LONG:
                return GetGlobalTypesHolder()->GlobalLongBoxBuiltinType();
            case TypeFlag::FLOAT:
                return GetGlobalTypesHolder()->GlobalFloatBoxBuiltinType();
            case TypeFlag::DOUBLE:
                return GetGlobalTypesHolder()->GlobalDoubleBoxBuiltinType();
            default: {
                Type *box = GetGlobalTypesHolder()->GlobalBoxBuiltinType()->Instantiate(allocator, Relation(),
                                                                                        GetGlobalTypesHolder());
                box->AddTypeFlag(checker::TypeFlag::GENERIC);
                box->AsETSObjectType()->TypeArguments().emplace_back(var_type);
                return box;
            }
        }
    }
    return var_type;
}

void ETSChecker::CheckForSameSwitchCases(ArenaVector<ir::SwitchCaseStatement *> *cases)
{
    //  Just to avoid extra nesting level
    auto const check_enum_type = [this](ir::Expression const *const case_test, ETSEnumType const *const type) -> void {
        if (case_test->TsType()->AsETSEnumType()->IsSameEnumLiteralType(type)) {
            ThrowTypeError("Case duplicate", case_test->Start());
        }
    };

    for (size_t case_num = 0; case_num < cases->size(); case_num++) {
        for (size_t compare_case = case_num + 1; compare_case < cases->size(); compare_case++) {
            auto *case_test = cases->at(case_num)->Test();
            auto *compare_case_test = cases->at(compare_case)->Test();

            if (case_test == nullptr || compare_case_test == nullptr) {
                continue;
            }

            if (case_test->TsType()->IsETSEnumType()) {
                check_enum_type(case_test, compare_case_test->TsType()->AsETSEnumType());
                continue;
            }

            if (case_test->IsIdentifier() || case_test->IsMemberExpression()) {
                CheckIdentifierSwitchCase(case_test, compare_case_test, cases->at(case_num)->Start());
                continue;
            }

            if (compare_case_test->IsIdentifier() || compare_case_test->IsMemberExpression()) {
                CheckIdentifierSwitchCase(compare_case_test, case_test, cases->at(compare_case)->Start());
                continue;
            }

            if (GetStringFromLiteral(case_test) != GetStringFromLiteral(compare_case_test)) {
                continue;
            }

            ThrowTypeError("Case duplicate", cases->at(compare_case)->Start());
        }
    }
}

std::string ETSChecker::GetStringFromIdentifierValue(checker::Type *case_type) const
{
    const auto identifier_type_kind = ETSChecker::TypeKind(case_type);
    switch (identifier_type_kind) {
        case TypeFlag::BYTE: {
            return std::to_string(case_type->AsByteType()->GetValue());
        }
        case TypeFlag::SHORT: {
            return std::to_string(case_type->AsShortType()->GetValue());
        }
        case TypeFlag::CHAR: {
            return std::to_string(case_type->AsCharType()->GetValue());
        }
        case TypeFlag::INT: {
            return std::to_string(case_type->AsIntType()->GetValue());
        }
        case TypeFlag::LONG: {
            return std::to_string(case_type->AsLongType()->GetValue());
        }
        case TypeFlag::ETS_OBJECT: {
            VarBinder()->ThrowError(case_type->AsETSObjectType()->Variable()->Declaration()->Node()->Start(),
                                    "not implemented");
        }
        default: {
            UNREACHABLE();
        }
    }
}

bool IsConstantMemberOrIdentifierExpression(ir::Expression *expression)
{
    if (expression->IsMemberExpression()) {
        return expression->AsMemberExpression()->PropVar()->Declaration()->IsConstDecl();
    }

    if (expression->IsIdentifier()) {
        return expression->AsIdentifier()->Variable()->Declaration()->IsConstDecl();
    }

    return false;
}

bool ETSChecker::CompareIdentifiersValuesAreDifferent(ir::Expression *compare_value, const std::string &case_value)
{
    if (IsConstantMemberOrIdentifierExpression(compare_value)) {
        checker::Type *compare_case_type = compare_value->TsType();

        const auto compare_case_value = GetStringFromIdentifierValue(compare_case_type);
        return case_value != compare_case_value;
    }

    return case_value != GetStringFromLiteral(compare_value);
}

void ETSChecker::CheckIdentifierSwitchCase(ir::Expression *current_case, ir::Expression *compare_case,
                                           const lexer::SourcePosition &pos)
{
    current_case->Check(this);

    if (!IsConstantMemberOrIdentifierExpression(current_case)) {
        ThrowTypeError("Constant expression required", pos);
    }

    checker::Type *case_type = current_case->TsType();

    if (!CompareIdentifiersValuesAreDifferent(compare_case, GetStringFromIdentifierValue(case_type))) {
        ThrowTypeError("Variable has same value with another switch case", pos);
    }
}

std::string ETSChecker::GetStringFromLiteral(ir::Expression *case_test) const
{
    switch (case_test->Type()) {
        case ir::AstNodeType::CHAR_LITERAL: {
            return std::to_string(case_test->AsCharLiteral()->Char());
        }
        case ir::AstNodeType::STRING_LITERAL:
        case ir::AstNodeType::NUMBER_LITERAL: {
            return util::Helpers::LiteralToPropName(case_test).Mutf8();
        }
        default:
            UNREACHABLE();
    }
}

bool ETSChecker::IsSameDeclarationType(varbinder::LocalVariable *target, varbinder::LocalVariable *compare)
{
    if (target->Declaration()->Type() != compare->Declaration()->Type()) {
        return false;
    }

    if ((target->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE) &&
         !compare->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE)) ||
        (!target->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE) &&
         compare->HasFlag(varbinder::VariableFlags::METHOD_REFERENCE))) {
        return false;
    }

    return true;
}

void ETSChecker::AddBoxingFlagToPrimitiveType(TypeRelation *relation, Type *target)
{
    auto boxing_result = PrimitiveTypeAsETSBuiltinType(target);
    if (boxing_result != nullptr) {
        relation->GetNode()->AddBoxingUnboxingFlags(GetBoxingFlag(boxing_result));
        relation->Result(true);
    }
}

void ETSChecker::AddUnboxingFlagToPrimitiveType(TypeRelation *relation, Type *source, Type *self)
{
    auto unboxing_result = UnboxingConverter(this, relation, source, self).Result();
    if ((unboxing_result != nullptr) && relation->IsTrue()) {
        relation->GetNode()->AddBoxingUnboxingFlags(GetUnboxingFlag(unboxing_result));
    }
}

void ETSChecker::CheckUnboxedTypeWidenable(TypeRelation *relation, Type *target, Type *self)
{
    checker::SavedTypeRelationFlagsContext saved_type_relation_flag_ctx(
        relation, TypeRelationFlag::ONLY_CHECK_WIDENING |
                      (relation->ApplyNarrowing() ? TypeRelationFlag::NARROWING : TypeRelationFlag::NONE));
    // NOTE: vpukhov. handle union type
    auto unboxed_type = ETSBuiltinTypeAsPrimitiveType(target);
    if (unboxed_type == nullptr) {
        return;
    }
    NarrowingWideningConverter(this, relation, unboxed_type, self);
    if (!relation->IsTrue()) {
        relation->Result(relation->IsAssignableTo(self, unboxed_type));
    }
}

void ETSChecker::CheckUnboxedTypesAssignable(TypeRelation *relation, Type *source, Type *target)
{
    auto *unboxed_source_type = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(source);
    auto *unboxed_target_type = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(target);
    if (unboxed_source_type == nullptr || unboxed_target_type == nullptr) {
        return;
    }
    relation->IsAssignableTo(unboxed_source_type, unboxed_target_type);
    if (relation->IsTrue()) {
        relation->GetNode()->AddBoxingUnboxingFlags(
            relation->GetChecker()->AsETSChecker()->GetUnboxingFlag(unboxed_source_type));
    }
}

void ETSChecker::CheckBoxedSourceTypeAssignable(TypeRelation *relation, Type *source, Type *target)
{
    checker::SavedTypeRelationFlagsContext saved_type_relation_flag_ctx(
        relation, (relation->ApplyWidening() ? TypeRelationFlag::WIDENING : TypeRelationFlag::NONE) |
                      (relation->ApplyNarrowing() ? TypeRelationFlag::NARROWING : TypeRelationFlag::NONE));
    auto *boxed_source_type = relation->GetChecker()->AsETSChecker()->PrimitiveTypeAsETSBuiltinType(source);
    if (boxed_source_type == nullptr) {
        return;
    }
    // Do not box primitive in case of cast to dynamic types
    if (target->IsETSDynamicType()) {
        return;
    }
    relation->IsAssignableTo(boxed_source_type, target);
    if (relation->IsTrue() && !relation->OnlyCheckBoxingUnboxing()) {
        AddBoxingFlagToPrimitiveType(relation, boxed_source_type);
    } else {
        auto unboxed_target_type = ETSBuiltinTypeAsPrimitiveType(target);
        if (unboxed_target_type == nullptr) {
            return;
        }
        NarrowingWideningConverter(this, relation, unboxed_target_type, source);
        if (relation->IsTrue()) {
            AddBoxingFlagToPrimitiveType(relation, target);
        }
    }
}

void ETSChecker::CheckUnboxedSourceTypeWithWideningAssignable(TypeRelation *relation, Type *source, Type *target)
{
    auto *unboxed_source_type = relation->GetChecker()->AsETSChecker()->ETSBuiltinTypeAsPrimitiveType(source);
    if (unboxed_source_type == nullptr) {
        return;
    }
    relation->IsAssignableTo(unboxed_source_type, target);
    if (!relation->IsTrue() && relation->ApplyWidening()) {
        relation->GetChecker()->AsETSChecker()->CheckUnboxedTypeWidenable(relation, target, unboxed_source_type);
    }
    if (!relation->OnlyCheckBoxingUnboxing()) {
        relation->GetNode()->AddBoxingUnboxingFlags(
            relation->GetChecker()->AsETSChecker()->GetUnboxingFlag(unboxed_source_type));
    }
}

bool ETSChecker::CheckRethrowingParams(const ir::AstNode *ancestor_function, const ir::AstNode *node)
{
    for (const auto param : ancestor_function->AsScriptFunction()->Signature()->Function()->Params()) {
        if (node->AsCallExpression()->Callee()->AsIdentifier()->Name().Is(
                param->AsETSParameterExpression()->Ident()->Name().Mutf8())) {
            return true;
        }
    }
    return false;
}

void ETSChecker::CheckThrowingStatements(ir::AstNode *node)
{
    ir::AstNode *ancestor_function = FindAncestorGivenByType(node, ir::AstNodeType::SCRIPT_FUNCTION);

    if (ancestor_function == nullptr) {
        ThrowTypeError(
            "This statement can cause an exception, therefore it must be enclosed in a try statement with a default "
            "catch clause",
            node->Start());
    }

    if (ancestor_function->AsScriptFunction()->IsThrowing() ||
        (ancestor_function->AsScriptFunction()->IsRethrowing() &&
         (!node->IsThrowStatement() && CheckRethrowingParams(ancestor_function, node)))) {
        return;
    }

    if (!CheckThrowingPlacement(node, ancestor_function)) {
        if (ancestor_function->AsScriptFunction()->IsRethrowing() && !node->IsThrowStatement()) {
            ThrowTypeError(
                "This statement can cause an exception, re-throwing functions can throw exception only by their "
                "parameters.",
                node->Start());
        }

        ThrowTypeError(
            "This statement can cause an exception, therefore it must be enclosed in a try statement with a default "
            "catch clause",
            node->Start());
    }
}

bool ETSChecker::CheckThrowingPlacement(ir::AstNode *node, const ir::AstNode *ancestor_function)
{
    ir::AstNode *start_point = node;
    ir::AstNode *enclosing_catch_clause = nullptr;
    ir::BlockStatement *enclosing_finally_block = nullptr;
    ir::AstNode *p = start_point->Parent();

    bool is_handled = false;
    const auto predicate_func = [&enclosing_catch_clause](ir::CatchClause *clause) {
        return clause == enclosing_catch_clause;
    };

    do {
        if (p->IsTryStatement() && p->AsTryStatement()->HasDefaultCatchClause()) {
            enclosing_catch_clause = FindAncestorGivenByType(start_point, ir::AstNodeType::CATCH_CLAUSE, p);
            enclosing_finally_block = FindFinalizerOfTryStatement(start_point, p);
            const auto catches = p->AsTryStatement()->CatchClauses();

            if (std::any_of(catches.begin(), catches.end(), predicate_func)) {
                start_point = enclosing_catch_clause;
            } else if (enclosing_finally_block != nullptr &&
                       enclosing_finally_block == p->AsTryStatement()->FinallyBlock()) {
                start_point = enclosing_finally_block;
            } else {
                is_handled = true;
                break;
            }
        }

        p = p->Parent();
    } while (p != ancestor_function);

    return is_handled;
}

ir::BlockStatement *ETSChecker::FindFinalizerOfTryStatement(ir::AstNode *start_from, const ir::AstNode *p)
{
    auto *iter = start_from->Parent();

    do {
        if (iter->IsBlockStatement()) {
            ir::BlockStatement *finally_block = iter->AsBlockStatement();

            if (finally_block == p->AsTryStatement()->FinallyBlock()) {
                return finally_block;
            }
        }

        iter = iter->Parent();
    } while (iter != p);

    return nullptr;
}

void ETSChecker::CheckRethrowingFunction(ir::ScriptFunction *func)
{
    bool found_throwing_param = false;

    // It doesn't support lambdas yet.
    for (auto item : func->Params()) {
        auto const *type = item->AsETSParameterExpression()->Ident()->TypeAnnotation();

        if (type->IsETSTypeReference()) {
            auto *type_decl = type->AsETSTypeReference()->Part()->Name()->AsIdentifier()->Variable()->Declaration();
            if (type_decl->IsTypeAliasDecl()) {
                type = type_decl->Node()->AsTSTypeAliasDeclaration()->TypeAnnotation();
            }
        }

        if (type->IsETSFunctionType() && type->AsETSFunctionType()->IsThrowing()) {
            found_throwing_param = true;
            break;
        }
    }

    if (!found_throwing_param) {
        ThrowTypeError("A rethrowing function must have a throwing function parameter", func->Start());
    }
}

ETSObjectType *ETSChecker::GetRelevantArgumentedTypeFromChild(ETSObjectType *const child, ETSObjectType *const target)
{
    if (child->GetDeclNode() == target->GetDeclNode()) {
        auto *relevant_type = CreateNewETSObjectType(child->Name(), child->GetDeclNode(), child->ObjectFlags());

        ArenaVector<Type *> params = child->TypeArguments();

        relevant_type->SetTypeArguments(std::move(params));
        relevant_type->SetEnclosingType(child->EnclosingType());
        relevant_type->SetSuperType(child->SuperType());

        return relevant_type;
    }

    assert(child->SuperType() != nullptr);

    return GetRelevantArgumentedTypeFromChild(child->SuperType(), target);
}

static void TypeToString(std::stringstream &ss, Type *tp)
{
    if (tp->IsETSObjectType() && tp->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::TYPE_PARAMETER)) {
        ss << tp->AsETSObjectType()->GetDeclNode()->Start().index;
        ss << ".";
    }
    if (tp->IsETSObjectType()) {
        ss << tp->AsETSObjectType()->Name();
    } else {
        tp->ToString(ss);
    }
    if (tp->IsETSObjectType() && !tp->AsETSObjectType()->TypeArguments().empty()) {
        auto type_args = tp->AsETSObjectType()->TypeArguments();
        ss << "<";
        for (auto *ta : type_args) {
            TypeToString(ss, ta);
            ss << ";";
        }
        ss << ">";
    }
}

util::StringView ETSChecker::GetHashFromTypeArguments(const ArenaVector<Type *> &type_arg_types)
{
    std::stringstream ss;

    for (auto *it : type_arg_types) {
        TypeToString(ss, it);
        ss << compiler::Signatures::MANGLE_SEPARATOR;
    }

    return util::UString(ss.str(), Allocator()).View();
}

util::StringView ETSChecker::GetHashFromSubstitution(const Substitution *substitution)
{
    std::vector<std::string> fields;
    for (auto [k, v] : *substitution) {
        std::stringstream ss;
        TypeToString(ss, k);
        ss << ":";
        TypeToString(ss, v);
        fields.push_back(ss.str());
    }
    std::sort(fields.begin(), fields.end());

    std::stringstream ss;
    for (auto &fstr : fields) {
        ss << fstr;
        ss << ";";
    }
    return util::UString(ss.str(), Allocator()).View();
}

ETSObjectType *ETSChecker::GetOriginalBaseType(Type *const object)
{
    if (object == nullptr || !object->IsETSObjectType()) {
        return nullptr;
    }

    return object->AsETSObjectType()->GetOriginalBaseType();
}

Type *ETSChecker::GetTypeFromTypeAnnotation(ir::TypeNode *const type_annotation)
{
    auto *type = type_annotation->GetType(this);

    if (!type_annotation->IsNullAssignable() && !type_annotation->IsUndefinedAssignable()) {
        return type;
    }

    if (!type->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT) && !type->HasTypeFlag(TypeFlag::ETS_UNION)) {
        ThrowTypeError("Non reference types cannot be nullish.", type_annotation->Start());
    }

    if (type->IsNullish()) {
        return type;
    }

    TypeFlag nullish_flags {0};
    if (type_annotation->IsNullAssignable()) {
        nullish_flags |= TypeFlag::NULL_TYPE;
    }
    if (type_annotation->IsUndefinedAssignable()) {
        nullish_flags |= TypeFlag::UNDEFINED;
    }
    return CreateNullishType(type, nullish_flags, Allocator(), Relation(), GetGlobalTypesHolder());
}

void ETSChecker::CheckValidGenericTypeParameter(Type *const arg_type, const lexer::SourcePosition &pos)
{
    if (!arg_type->IsETSEnumType() && !arg_type->IsETSStringEnumType()) {
        return;
    }
    std::stringstream ss;
    arg_type->ToString(ss);
    ThrowTypeError("Type '" + ss.str() + "' is not valid for generic type arguments", pos);
}

void ETSChecker::CheckNumberOfTypeArguments(Type *const type, ir::TSTypeParameterDeclaration *const type_param_decl,
                                            ir::TSTypeParameterInstantiation *const type_args,
                                            const lexer::SourcePosition &pos)
{
    if (type_param_decl != nullptr && type_args == nullptr) {
        ThrowTypeError({"Type '", type, "' is generic but type argument were not provided."}, pos);
    }

    if (type_param_decl == nullptr && type_args != nullptr) {
        ThrowTypeError({"Type '", type, "' is not generic."}, pos);
    }

    if (type_args == nullptr) {
        return;
    }

    ASSERT(type_param_decl != nullptr && type_args != nullptr);
    if (type_param_decl->Params().size() != type_args->Params().size()) {
        ThrowTypeError({"Type '", type, "' has ", type_param_decl->Params().size(), " number of type parameters, but ",
                        type_args->Params().size(), " type arguments were provided."},
                       pos);
    }
}

bool ETSChecker::NeedTypeInference(const ir::ScriptFunction *lambda)
{
    if (lambda->ReturnTypeAnnotation() == nullptr) {
        return true;
    }
    for (auto *const param : lambda->Params()) {
        const auto *const lambda_param = param->AsETSParameterExpression()->Ident();
        if (lambda_param->TypeAnnotation() == nullptr) {
            return true;
        }
    }
    return false;
}

std::vector<bool> ETSChecker::FindTypeInferenceArguments(const ArenaVector<ir::Expression *> &arguments)
{
    std::vector<bool> arg_type_inference_required(arguments.size());
    size_t index = 0;
    for (ir::Expression *arg : arguments) {
        if (arg->IsArrowFunctionExpression()) {
            ir::ScriptFunction *const lambda = arg->AsArrowFunctionExpression()->Function();
            if (NeedTypeInference(lambda)) {
                arg_type_inference_required[index] = true;
            }
        }
        ++index;
    }
    return arg_type_inference_required;
}

static ir::AstNode *DerefETSTypeReference(ir::AstNode *node)
{
    ASSERT(node->IsETSTypeReference());
    do {
        auto *name = node->AsETSTypeReference()->Part()->Name();
        ASSERT(name->IsIdentifier());
        auto *var = name->AsIdentifier()->Variable();
        ASSERT(var != nullptr);
        auto *decl_node = var->Declaration()->Node();
        if (!decl_node->IsTSTypeAliasDeclaration()) {
            return decl_node;
        }
        node = decl_node->AsTSTypeAliasDeclaration()->TypeAnnotation();
    } while (node->IsETSTypeReference());
    return node;
}

bool ETSChecker::CheckLambdaAssignable(ir::Expression *param, ir::ScriptFunction *lambda)
{
    ASSERT(param->IsETSParameterExpression());
    ir::AstNode *type_ann = param->AsETSParameterExpression()->Ident()->TypeAnnotation();
    if (type_ann->IsETSTypeReference()) {
        type_ann = DerefETSTypeReference(type_ann);
    }
    if (!type_ann->IsETSFunctionType()) {
        return false;
    }
    ir::ETSFunctionType *callee_type = type_ann->AsETSFunctionType();
    return lambda->Params().size() == callee_type->Params().size();
}

void ETSChecker::InferTypesForLambda(ir::ScriptFunction *lambda, ir::ETSFunctionType *callee_type)
{
    for (size_t i = 0; i < callee_type->Params().size(); ++i) {
        const auto *const callee_param = callee_type->Params()[i]->AsETSParameterExpression()->Ident();
        auto *const lambda_param = lambda->Params()[i]->AsETSParameterExpression()->Ident();
        if (lambda_param->TypeAnnotation() == nullptr) {
            lambda_param->SetTsTypeAnnotation(callee_param->TypeAnnotation());
        }
    }
    if (lambda->ReturnTypeAnnotation() == nullptr) {
        lambda->SetReturnTypeAnnotation(callee_type->ReturnType());
    }
}

bool ETSChecker::TypeInference(Signature *signature, const ArenaVector<ir::Expression *> &arguments,
                               TypeRelationFlag flags)
{
    bool invocable = true;
    auto const argument_count = arguments.size();
    auto const parameter_count = signature->Params().size();
    auto const count = std::min(parameter_count, argument_count);

    for (size_t index = 0U; index < count; ++index) {
        auto const &argument = arguments[index];
        if (!argument->IsArrowFunctionExpression()) {
            continue;
        }

        if (index == arguments.size() - 1 && (flags & TypeRelationFlag::NO_CHECK_TRAILING_LAMBDA) != 0) {
            continue;
        }

        auto *const arrow_func_expr = argument->AsArrowFunctionExpression();
        ir::ScriptFunction *const lambda = arrow_func_expr->Function();
        if (!NeedTypeInference(lambda)) {
            continue;
        }

        auto const *const param = signature->Function()->Params()[index]->AsETSParameterExpression()->Ident();
        ir::AstNode *type_ann = param->TypeAnnotation();

        if (type_ann->IsETSTypeReference()) {
            type_ann = DerefETSTypeReference(type_ann);
        }

        ASSERT(type_ann->IsETSFunctionType());
        InferTypesForLambda(lambda, type_ann->AsETSFunctionType());
        Type *const arg_type = arrow_func_expr->Check(this);

        checker::InvocationContext invokation_ctx(
            Relation(), arguments[index], arg_type, signature->Params()[index]->TsType(), arrow_func_expr->Start(),
            {"Call argument at index ", index, " is not compatible with the signature's type at that index"}, flags);

        invocable &= invokation_ctx.IsInvocable();
    }
    return invocable;
}

void ETSChecker::AddUndefinedParamsForDefaultParams(const Signature *const signature,
                                                    ArenaVector<panda::es2panda::ir::Expression *> &arguments,
                                                    ETSChecker *checker)
{
    if (!signature->Function()->IsDefaultParamProxy() || signature->Function()->Params().size() <= arguments.size()) {
        return;
    }

    uint32_t num = 0;
    for (size_t i = arguments.size(); i != signature->Function()->Params().size() - 1; i++) {
        if (auto const *const param = signature->Function()->Params()[i]->AsETSParameterExpression();
            !param->IsRestParameter()) {
            auto const *const type_ann = param->Ident()->TypeAnnotation();
            if (type_ann->IsETSPrimitiveType()) {
                if (type_ann->AsETSPrimitiveType()->GetPrimitiveType() == ir::PrimitiveType::BOOLEAN) {
                    arguments.push_back(checker->Allocator()->New<ir::BooleanLiteral>(false));
                } else {
                    arguments.push_back(checker->Allocator()->New<ir::NumberLiteral>(lexer::Number(0)));
                }
            } else {
                // A proxy-function is called, so default reference parameters
                // are initialized with null instead of undefined
                auto *const null_literal = checker->Allocator()->New<ir::NullLiteral>();
                null_literal->SetTsType(checker->GlobalETSNullType());
                arguments.push_back(null_literal);
            }
            num |= (1U << (arguments.size() - 1));
        }
    }
    arguments.push_back(checker->Allocator()->New<ir::NumberLiteral>(lexer::Number(num)));
}

bool ETSChecker::ExtensionETSFunctionType(checker::Type *type)
{
    if (!type->IsETSFunctionType()) {
        return false;
    }

    for (auto *signature : type->AsETSFunctionType()->CallSignatures()) {
        if (signature->Function()->IsExtensionMethod()) {
            return true;
        }
    }

    return false;
}

void ETSChecker::ValidateTupleMinElementSize(ir::ArrayExpression *const array_expr, ETSTupleType *tuple)
{
    if (array_expr->Elements().size() < static_cast<size_t>(tuple->GetMinTupleSize())) {
        ThrowTypeError({"Few elements in array initializer for tuple with size of ",
                        static_cast<size_t>(tuple->GetMinTupleSize())},
                       array_expr->Start());
    }
}

void ETSChecker::ModifyPreferredType(ir::ArrayExpression *const array_expr, Type *const new_preferred_type)
{
    // After modifying the preferred type of an array expression, it needs to be rechecked at the call site
    array_expr->SetPreferredType(new_preferred_type);
    array_expr->SetTsType(nullptr);

    for (auto *const element : array_expr->Elements()) {
        if (element->IsArrayExpression()) {
            ModifyPreferredType(element->AsArrayExpression(), nullptr);
        }
    }
}

bool ETSChecker::TryTransformingToStaticInvoke(ir::Identifier *const ident, const Type *resolved_type)
{
    ASSERT(ident->Parent()->IsCallExpression());
    ASSERT(ident->Parent()->AsCallExpression()->Callee() == ident);

    if (!resolved_type->IsETSObjectType()) {
        return false;
    }

    auto class_name = ident->Name();
    std::string_view property_name;

    PropertySearchFlags search_flag = PropertySearchFlags::SEARCH_IN_INTERFACES | PropertySearchFlags::SEARCH_IN_BASE |
                                      PropertySearchFlags::SEARCH_STATIC_METHOD;
    auto *instantiate_method =
        resolved_type->AsETSObjectType()->GetProperty(compiler::Signatures::STATIC_INSTANTIATE_METHOD, search_flag);
    if (instantiate_method != nullptr) {
        property_name = compiler::Signatures::STATIC_INSTANTIATE_METHOD;
    } else if (auto *invoke_method = resolved_type->AsETSObjectType()->GetProperty(
                   compiler::Signatures::STATIC_INVOKE_METHOD, search_flag);
               invoke_method != nullptr) {
        property_name = compiler::Signatures::STATIC_INVOKE_METHOD;
    } else {
        ThrowTypeError({"No static ", compiler::Signatures::STATIC_INVOKE_METHOD, " method and static ",
                        compiler::Signatures::STATIC_INSTANTIATE_METHOD, " method in ", class_name, ". ", class_name,
                        "() is not allowed."},
                       ident->Start());
    }

    auto *class_id = AllocNode<ir::Identifier>(class_name, Allocator());
    auto *method_id = AllocNode<ir::Identifier>(property_name, Allocator());
    auto *transformed_callee =
        AllocNode<ir::MemberExpression>(class_id, method_id, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    class_id->SetRange(ident->Range());
    method_id->SetRange(ident->Range());
    transformed_callee->SetRange(ident->Range());

    auto *call_expr = ident->Parent()->AsCallExpression();
    transformed_callee->SetParent(call_expr);
    call_expr->SetCallee(transformed_callee);

    if (instantiate_method != nullptr) {
        std::string implicit_instantiate_argument = "()=>{return new " + std::string(class_name) + "()}";

        parser::Program program(Allocator(), VarBinder());
        es2panda::CompilerOptions options;
        auto parser = parser::ETSParser(&program, options, parser::ParserStatus::NO_OPTS);
        auto *arg_expr = parser.CreateExpression(implicit_instantiate_argument);
        compiler::ScopesInitPhaseETS::RunExternalNode(arg_expr, &program);

        arg_expr->SetParent(call_expr);
        arg_expr->SetRange(ident->Range());

        VarBinder()->AsETSBinder()->HandleCustomNodes(arg_expr);

        auto &arguments = call_expr->Arguments();
        arguments.insert(arguments.begin(), arg_expr);
    }

    return true;
}
}  // namespace panda::es2panda::checker
