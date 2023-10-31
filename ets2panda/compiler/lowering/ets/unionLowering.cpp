/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "unionLowering.h"
#include "varbinder/variableFlags.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "compiler/core/compilerContext.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/opaqueTypeNode.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/ts/tsAsExpression.h"
#include "type_helper.h"

namespace panda::es2panda::compiler {

std::string const &UnionLowering::Name()
{
    static std::string const NAME = "union-property-access";
    return NAME;
}

ir::ClassDefinition *CreateUnionFieldClass(checker::ETSChecker *checker, varbinder::VarBinder *varbinder)
{
    // Create the name for the synthetic class node
    util::UString union_field_class_name(util::StringView(panda_file::GetDummyClassName()), checker->Allocator());
    varbinder::Variable *found_var = nullptr;
    if ((found_var = checker->Scope()->FindLocal(union_field_class_name.View(),
                                                 varbinder::ResolveBindingOptions::BINDINGS)) != nullptr) {
        return found_var->Declaration()->Node()->AsClassDeclaration()->Definition();
    }
    auto *ident = checker->AllocNode<ir::Identifier>(union_field_class_name.View(), checker->Allocator());
    auto [decl, var] = varbinder->NewVarDecl<varbinder::ClassDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);

    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(varbinder);
    auto *class_def = checker->AllocNode<ir::ClassDefinition>(checker->Allocator(), class_ctx.GetScope(), ident,
                                                              ir::ClassDefinitionModifiers::GLOBAL,
                                                              ir::ModifierFlags::NONE, Language(Language::Id::ETS));

    auto *class_decl = checker->AllocNode<ir::ClassDeclaration>(class_def, checker->Allocator());
    class_def->Scope()->BindNode(class_decl);
    class_def->SetTsType(checker->GlobalETSObjectType());
    decl->BindNode(class_decl);
    var->SetScope(class_def->Scope());

    varbinder->AsETSBinder()->BuildClassDefinition(class_def);
    return class_def;
}

void CreateUnionFieldClassProperty(ArenaAllocator *allocator, varbinder::VarBinder *varbinder,
                                   ir::ClassDefinition *class_def, checker::Type *field_type,
                                   const util::StringView &prop_name)
{
    auto *class_scope = class_def->Scope()->AsClassScope();
    // Enter the union filed class instance field scope
    auto field_ctx =
        varbinder::LexicalScope<varbinder::LocalScope>::Enter(varbinder, class_scope->InstanceFieldScope());

    if (class_scope->FindLocal(prop_name, varbinder::ResolveBindingOptions::VARIABLES) != nullptr) {
        return;
    }

    // Create field name for synthetic class
    auto *field_ident = allocator->New<ir::Identifier>(prop_name, allocator);

    // Create the synthetic class property node
    auto *field =
        allocator->New<ir::ClassProperty>(field_ident, nullptr, nullptr, ir::ModifierFlags::NONE, allocator, false);

    // Add the declaration to the scope
    auto [decl, var] = varbinder->NewVarDecl<varbinder::LetDecl>(field_ident->Start(), field_ident->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(field_type);
    field_ident->SetVariable(var);
    field->SetTsType(field_type);
    decl->BindNode(field);

    ArenaVector<ir::AstNode *> field_decl {allocator->Adapter()};
    field_decl.push_back(field);
    class_def->AddProperties(std::move(field_decl));
}

ir::Expression *HandleUnionPropertyAccess(checker::ETSChecker *checker, varbinder::VarBinder *varbinder,
                                          ir::MemberExpression *expr)
{
    auto *class_def = CreateUnionFieldClass(checker, varbinder);
    CreateUnionFieldClassProperty(checker->Allocator(), varbinder, class_def, expr->PropVar()->TsType(),
                                  expr->Property()->AsIdentifier()->Name());
    if (expr->Object()->IsIdentifier()) {
        auto *new_ts_type = expr->Object()->TsType()->AsETSUnionType()->GetLeastUpperBoundType(checker);
        expr->Object()->AsIdentifier()->Variable()->SetTsType(new_ts_type);
    }
    return expr;
}

ir::Expression *HandleUnionFunctionParameter(checker::ETSChecker *checker, ir::ETSParameterExpression *param)
{
    auto *union_type = param->Ident()->Variable()->TsType()->AsETSUnionType();
    param->Ident()->Variable()->SetTsType(union_type->GetLeastUpperBoundType(checker));
    return param;
}

ir::Expression *HandleBinaryExpressionWithUnion(checker::ETSChecker *checker, ir::BinaryExpression *expr)
{
    auto *union_type = expr->OperationType()->AsETSUnionType();
    ir::Expression *union_node;
    ir::Expression *other_union_node = nullptr;
    checker::Type *other_node_type;
    if (expr->Left()->TsType()->IsETSUnionType()) {
        union_node = expr->Left();
        other_node_type = expr->Right()->TsType();
        if (other_node_type->IsETSUnionType()) {
            other_union_node = expr->Right();
        }
    } else {
        union_node = expr->Right();
        other_node_type = expr->Left()->TsType();
    }
    auto *source_type =
        union_type->AsETSUnionType()->FindTypeIsCastableToSomeType(union_node, checker->Relation(), other_node_type);
    if (source_type == nullptr) {
        checker->ThrowTypeError("Bad operand type, some type of the union must be the same type as other expression.",
                                expr->Start());
    }
    if ((union_node->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG) != 0U &&
        source_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        union_node->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);
    }
    auto *union_type_node = checker->AllocNode<ir::OpaqueTypeNode>(source_type);
    auto *as_expression = checker->AllocNode<ir::TSAsExpression>(union_node, union_type_node, false);
    as_expression->SetParent(expr);
    expr->SetOperationType(source_type);
    if (other_union_node != nullptr) {
        auto *other_union_type_node = checker->AllocNode<ir::OpaqueTypeNode>(other_node_type);
        auto *other_as_expression =
            checker->AllocNode<ir::TSAsExpression>(other_union_node, other_union_type_node, false);
        other_as_expression->SetParent(expr);
    }
    expr->SetTsType(checker->GlobalETSBooleanType());
    return expr;
}

bool UnionLowering::Perform(CompilerContext *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : ext_programs) {
            Perform(ctx, ext_prog);
        }
    }

    checker::ETSChecker *checker = ctx->Checker()->AsETSChecker();

    program->Ast()->TransformChildrenRecursively([checker, ctx](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr &&
            ast->AsMemberExpression()->Object()->TsType()->IsETSUnionType()) {
            return HandleUnionPropertyAccess(checker, ctx->VarBinder(), ast->AsMemberExpression());
        }

        if (ast->IsETSParameterExpression() &&
            ast->AsETSParameterExpression()->Ident()->Variable()->TsType() != nullptr &&
            ast->AsETSParameterExpression()->Ident()->Variable()->TsType()->IsETSUnionType()) {
            return HandleUnionFunctionParameter(checker, ast->AsETSParameterExpression());
        }

        if (ast->IsBinaryExpression() && ast->AsBinaryExpression()->OperationType() != nullptr &&
            ast->AsBinaryExpression()->OperationType()->IsETSUnionType()) {
            return HandleBinaryExpressionWithUnion(checker, ast->AsBinaryExpression());
        }

        return ast;
    });

    return true;
}

bool UnionLowering::Postcondition(CompilerContext *ctx, const parser::Program *program)
{
    if (ctx->Options()->compilation_mode != CompilationMode::GEN_STD_LIB) {
        return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
            return ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr &&
                   ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType()->IsETSUnionType() &&
                   ast->AsMemberExpression()->Object()->IsIdentifier() &&
                   ast->AsMemberExpression()->Object()->AsIdentifier()->Variable()->TsType()->IsETSUnionType();
        });
    }

    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : ext_programs) {
            if (!Postcondition(ctx, ext_prog)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        return ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr &&
               ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType()->IsETSUnionType() &&
               ast->AsMemberExpression()->Object()->IsIdentifier() &&
               ast->AsMemberExpression()->Object()->AsIdentifier()->Variable()->TsType()->IsETSUnionType();
    });
}

}  // namespace panda::es2panda::compiler
