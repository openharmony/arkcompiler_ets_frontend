/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "ETSAnalyzer.h"

#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/typeRelationContext.h"
#include "util/helpers.h"

namespace panda::es2panda::checker {

ETSChecker *ETSAnalyzer::GetETSChecker() const
{
    return static_cast<ETSChecker *>(GetChecker());
}

// from as folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NamedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
}
// from base folder
checker::Type *ETSAnalyzer::Check(ir::CatchClause *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ETSObjectType *exception_type = checker->GlobalETSObjectType();

    ir::Identifier *param_ident = st->Param()->AsIdentifier();

    if (param_ident->TypeAnnotation() != nullptr) {
        checker::Type *catch_param_annotation_type = param_ident->TypeAnnotation()->GetType(checker);

        exception_type = checker->CheckExceptionOrErrorType(catch_param_annotation_type, st->Param()->Start());
    }

    param_ident->Variable()->SetTsType(exception_type);

    st->Body()->Check(checker);

    st->SetTsType(exception_type);
    return exception_type;
}

checker::Type *ETSAnalyzer::Check(ir::ClassDefinition *node) const
{
    ETSChecker *checker = GetETSChecker();
    if (node->TsType() == nullptr) {
        checker->BuildClassProperties(node);
    }

    checker->CheckClassDefinition(node);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ClassProperty *st) const
{
    ASSERT(st->Id() != nullptr);
    ETSChecker *checker = GetETSChecker();

    if (st->TsType() != nullptr) {
        return st->TsType();
    }

    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass(),
                                               checker->Context().ContainingSignature());

    if (st->IsStatic()) {
        checker->AddStatus(checker::CheckerStatus::IN_STATIC_CONTEXT);
    }

    st->SetTsType(checker->CheckVariableDeclaration(st->Id(), st->TypeAnnotation(), st->Value(), st->Modifiers()));

    return st->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::ClassStaticBlock *st) const
{
    ETSChecker *checker = GetETSChecker();

    if (checker->HasStatus(checker::CheckerStatus::INNER_CLASS)) {
        checker->ThrowTypeError("Static initializer is not allowed in inner class.", st->Start());
    }

    auto *func = st->Function();
    st->SetTsType(checker->BuildFunctionSignature(func));
    checker::ScopeContext scope_ctx(checker, func->Scope());
    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_STATIC_BLOCK | checker::CheckerStatus::IN_STATIC_CONTEXT);
    func->Body()->Check(checker);
    return st->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::Decorator *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::MetaProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::MethodDefinition *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::Property *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ScriptFunction *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::SpreadElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TemplateElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSIndexSignature *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSMethodSignature *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSPropertySignature *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSSignatureDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}
// from ets folder
checker::Type *ETSAnalyzer::Check(ir::ETSClassLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSImportDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSLaunchExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSPackageDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ETSParameterExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() == nullptr) {
        checker::Type *param_type;

        if (expr->Ident()->TsType() != nullptr) {
            param_type = expr->Ident()->TsType();
        } else {
            param_type = !expr->IsRestParameter() ? expr->Ident()->Check(checker) : expr->spread_->Check(checker);
            if (expr->IsDefault()) {
                [[maybe_unused]] auto *const init_type = expr->Initializer()->Check(checker);
            }
        }

        expr->SetTsType(param_type);
    }

    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSPrimitiveType *node) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ETSStructDeclaration *node) const
{
    ETSChecker *checker = GetETSChecker();
    node->Definition()->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ETSTypeReference *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check(ir::ETSTypeReferencePart *node) const
{
    ETSChecker *checker = GetETSChecker();
    return node->GetType(checker);
}

checker::Type *ETSAnalyzer::Check(ir::ETSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSWildcardType *node) const
{
    UNREACHABLE();
}
// compile methods for EXPRESSIONS in alphabetical order
checker::Type *ETSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ArrowFunctionExpression *expr) const
{
    ETSChecker *checker = GetETSChecker();
    if (expr->TsType() != nullptr) {
        return expr->TsType();
    }

    auto *func_type = checker->BuildFunctionSignature(expr->Function(), false);

    if (expr->Function()->IsAsyncFunc()) {
        auto *ret_type = static_cast<checker::ETSObjectType *>(expr->Function()->Signature()->ReturnType());
        if (ret_type->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
            checker->ThrowTypeError("Return type of async lambda must be 'Promise'", expr->Function()->Start());
        }
    }

    checker::ScopeContext scope_ctx(checker, expr->Function()->Scope());

    if (checker->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD)) {
        /*
        example code:
        ```
            class A {
                prop:number
            }
            function A.method() {
                let a = () => {
                    console.println(this.prop)
                }
            }
        ```
        here the enclosing class of arrow function should be Class A
        */
        checker->Context().SetContainingClass(
            checker->Scope()->Find(varbinder::VarBinder::MANDATORY_PARAM_THIS).variable->TsType()->AsETSObjectType());
    }

    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_LAMBDA);
    checker->Context().SetContainingSignature(func_type->CallSignatures()[0]);

    auto *body_type = expr->Function()->Body()->Check(checker);

    if (expr->Function()->Body()->IsExpression()) {
        if (expr->Function()->ReturnTypeAnnotation() == nullptr) {
            func_type->CallSignatures()[0]->SetReturnType(body_type);
        }

        checker::AssignmentContext(
            checker->Relation(), expr->Function()->Body()->AsExpression(), body_type,
            func_type->CallSignatures()[0]->ReturnType(), expr->Function()->Start(),
            {"Return statements return type is not compatible with the containing functions return type"},
            checker::TypeRelationFlag::DIRECT_RETURN);
    }

    checker->Context().SetContainingSignature(nullptr);
    checker->CheckCapturedVariables();

    for (auto [var, _] : checker->Context().CapturedVars()) {
        (void)_;
        expr->CapturedVars().push_back(var);
    }

    expr->SetTsType(func_type);
    return expr->TsType();
}

checker::Type *ETSAnalyzer::Check(ir::AssignmentExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::AwaitExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::BlockExpression *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::CallExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ChainExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ClassExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ConditionalExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::DirectEvalExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::FunctionExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::Identifier *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ImportExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::MemberExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::NewExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ObjectExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::OmittedExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::OpaqueTypeNode *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::SequenceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::SuperExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TaggedTemplateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TemplateLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ThisExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::UnaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::UpdateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::YieldExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}
// compile methods for LITERAL EXPRESSIONS in alphabetical order
checker::Type *ETSAnalyzer::Check(ir::BigIntLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::BooleanLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::CharLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::NullLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::NumberLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::RegExpLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::StringLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::UndefinedLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
checker::Type *ETSAnalyzer::Check(ir::ExportAllDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ExportDefaultDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ExportNamedDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ExportSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ImportDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::Type *type = nullptr;
    for (auto *spec : st->Specifiers()) {
        if (spec->IsImportNamespaceSpecifier()) {
            type = spec->AsImportNamespaceSpecifier()->Check(checker);
        }
    }

    return type;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportDefaultSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ImportNamespaceSpecifier *st) const
{
    ETSChecker *checker = GetETSChecker();
    if (st->Local()->Name().Empty()) {
        return nullptr;
    }

    if (st->Local()->AsIdentifier()->TsType() != nullptr) {
        return st->Local()->TsType();
    }

    auto *import_decl = st->Parent()->AsETSImportDeclaration();
    auto import_path = import_decl->Source()->Str();

    if (import_decl->IsPureDynamic()) {
        auto *type = checker->GlobalBuiltinDynamicType(import_decl->Language());
        checker->SetrModuleObjectTsType(st->Local(), type);
        return type;
    }

    std::string package_name =
        (import_decl->Module() == nullptr) ? import_path.Mutf8() : import_decl->Module()->Str().Mutf8();

    std::replace(package_name.begin(), package_name.end(), '/', '.');
    util::UString package_path(package_name, checker->Allocator());
    std::vector<util::StringView> synthetic_names = checker->GetNameForSynteticObjectType(package_path.View());

    ASSERT(!synthetic_names.empty());

    auto assembler_name = synthetic_names[0];
    if (import_decl->Module() != nullptr) {
        assembler_name = util::UString(assembler_name.Mutf8().append(".").append(compiler::Signatures::ETS_GLOBAL),
                                       checker->Allocator())
                             .View();
    }

    auto *module_object_type =
        checker->Allocator()->New<checker::ETSObjectType>(checker->Allocator(), synthetic_names[0], assembler_name,
                                                          st->Local()->AsIdentifier(), checker::ETSObjectFlags::CLASS);

    auto *root_decl = checker->Allocator()->New<varbinder::ClassDecl>(synthetic_names[0]);
    varbinder::LocalVariable *root_var =
        checker->Allocator()->New<varbinder::LocalVariable>(root_decl, varbinder::VariableFlags::NONE);
    root_var->SetTsType(module_object_type);

    synthetic_names.erase(synthetic_names.begin());
    checker::ETSObjectType *last_object_type(module_object_type);

    for (const auto &synthetic_name : synthetic_names) {
        auto *synthetic_obj_type = checker->Allocator()->New<checker::ETSObjectType>(
            checker->Allocator(), synthetic_name, synthetic_name, st->Local()->AsIdentifier(),
            checker::ETSObjectFlags::NO_OPTS);

        auto *class_decl = checker->Allocator()->New<varbinder::ClassDecl>(synthetic_name);
        varbinder::LocalVariable *var =
            checker->Allocator()->New<varbinder::LocalVariable>(class_decl, varbinder::VariableFlags::CLASS);
        var->SetTsType(synthetic_obj_type);
        last_object_type->AddProperty<checker::PropertyType::STATIC_FIELD>(var);
        synthetic_obj_type->SetEnclosingType(last_object_type);
        last_object_type = synthetic_obj_type;
    }

    checker->SetPropertiesForModuleObject(
        last_object_type,
        (import_decl->Module() != nullptr)
            ? util::UString(import_path.Mutf8() + import_decl->Module()->Str().Mutf8(), checker->Allocator()).View()
            : import_path);
    checker->SetrModuleObjectTsType(st->Local(), last_object_type);

    return module_object_type;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportSpecifier *st) const
{
    UNREACHABLE();
}
// compile methods for STATEMENTS in alphabetical order
checker::Type *ETSAnalyzer::Check(ir::AssertStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::BlockStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::BreakStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::ClassDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->Definition()->Check(checker);
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ContinueStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->target_ = checker->FindJumpTarget(st->Type(), st, st->Ident());
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::DebuggerStatement *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::DoWhileStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    checker->CheckTruthinessOfType(st->Test());
    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::EmptyStatement *st) const
{
    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ExpressionStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    return st->GetExpression()->Check(checker);
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ForInStatement *st) const
{
    UNREACHABLE();
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const INVALID_SOURCE_EXPR_TYPE[] =
    "'For-of' statement source expression should be either a string or an array.";
static constexpr char const INVALID_CONST_ASSIGNMENT[] = "Cannot assign a value to a constant variable ";
static constexpr char const ITERATOR_TYPE_ABSENT[] = "Cannot obtain iterator type in 'for-of' statement.";
// NOLINTEND(modernize-avoid-c-arrays)

checker::Type *ETSAnalyzer::Check(ir::ForOfStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    checker::Type *const expr_type = st->Right()->Check(checker);
    checker::Type *elem_type;

    if (expr_type == nullptr || (!expr_type->IsETSArrayType() && !expr_type->IsETSStringType())) {
        checker->ThrowTypeError(INVALID_SOURCE_EXPR_TYPE, st->Right()->Start());
    } else if (expr_type->IsETSStringType()) {
        elem_type = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else {
        elem_type = expr_type->AsETSArrayType()->ElementType()->Instantiate(checker->Allocator(), checker->Relation(),
                                                                            checker->GetGlobalTypesHolder());
        elem_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    }

    st->Left()->Check(checker);
    checker::Type *iter_type = nullptr;

    // Just to avoid extra nested level(s)
    auto const get_iter_type = [checker, elem_type](ir::VariableDeclarator *const declarator) -> checker::Type * {
        if (declarator->TsType() == nullptr) {
            if (auto *resolved = checker->FindVariableInFunctionScope(declarator->Id()->AsIdentifier()->Name());
                resolved != nullptr) {
                resolved->SetTsType(elem_type);
                return elem_type;
            }
        } else {
            return declarator->TsType();
        }
        return nullptr;
    };

    if (st->Left()->IsIdentifier()) {
        if (auto *const variable = st->Left()->AsIdentifier()->Variable(); variable != nullptr) {
            if (variable->Declaration()->IsConstDecl()) {
                checker->ThrowTypeError({INVALID_CONST_ASSIGNMENT, variable->Name()},
                                        variable->Declaration()->Node()->Start());
            }
        }
        iter_type = st->Left()->AsIdentifier()->TsType();
    } else if (st->Left()->IsVariableDeclaration()) {
        if (auto const &declarators = st->Left()->AsVariableDeclaration()->Declarators(); !declarators.empty()) {
            iter_type = get_iter_type(declarators.front());
        }
    }

    if (iter_type == nullptr) {
        checker->ThrowTypeError(ITERATOR_TYPE_ABSENT, st->Left()->Start());
    }

    auto *const relation = checker->Relation();
    relation->SetFlags(checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
    relation->SetNode(checker->AllocNode<ir::SuperExpression>());  // Dummy node to avoid assertion!

    if (!relation->IsAssignableTo(elem_type, iter_type)) {
        std::stringstream ss {};
        ss << "Source element type '";
        elem_type->ToString(ss);
        ss << "' is not assignable to the loop iterator type '";
        iter_type->ToString(ss);
        ss << "'.";
        checker->ThrowTypeError(ss.str(), st->Start());
    }

    relation->SetNode(nullptr);
    relation->SetFlags(checker::TypeRelationFlag::NONE);

    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ForUpdateStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    if (st->Init() != nullptr) {
        st->Init()->Check(checker);
    }

    if (st->Test() != nullptr) {
        checker->CheckTruthinessOfType(st->Test());
    }

    if (st->Update() != nullptr) {
        st->Update()->Check(checker);
    }

    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::FunctionDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::IfStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker->CheckTruthinessOfType(st->test_);

    st->consequent_->Check(checker);

    if (st->Alternate() != nullptr) {
        st->alternate_->Check(checker);
    }

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::LabelledStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    st->body_->Check(checker);
    return nullptr;
}

void CheckArgumentVoidType(checker::Type *&func_return_type, ETSChecker *checker, const std::string &name,
                           ir::ReturnStatement *st)
{
    if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
        if (func_return_type == checker->GlobalBuiltinVoidType()) {
            func_return_type = checker->GlobalVoidType();
        } else if (!func_return_type->IsETSVoidType() && !func_return_type->IsIntType()) {
            checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
        }
    }
}

void CheckReturnType(ETSChecker *checker, checker::Type *func_return_type, checker::Type *argument_type,
                     ir::Expression *st_argument)
{
    if (func_return_type->IsETSVoidType() || func_return_type == checker->GlobalBuiltinVoidType()) {
        if (argument_type != checker->GlobalVoidType() && argument_type != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("Unexpected return value, enclosing method return type is void.",
                                    st_argument->Start());
        }
    } else {
        checker::AssignmentContext(checker->Relation(), st_argument, argument_type, func_return_type,
                                   st_argument->Start(),
                                   {"Return statement type is not compatible with the enclosing method's return type."},
                                   checker::TypeRelationFlag::DIRECT_RETURN);
    }
}

void InferReturnType(ETSChecker *checker, ir::ScriptFunction *containing_func, checker::Type *&func_return_type,
                     ir::Expression *st_argument)
{
    //  First (or single) return statement in the function:
    func_return_type = st_argument == nullptr ? checker->GlobalBuiltinVoidType() : st_argument->Check(checker);
    if (func_return_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
        // remove CONSTANT type modifier if exists
        func_return_type =
            func_return_type->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
        func_return_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    }

    containing_func->Signature()->SetReturnType(func_return_type);
    containing_func->Signature()->RemoveSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE);
    checker->VarBinder()->AsETSBinder()->BuildFunctionName(containing_func);

    if (st_argument != nullptr && st_argument->IsObjectExpression()) {
        st_argument->AsObjectExpression()->SetPreferredType(func_return_type);
    }
}

void ProcessReturnStatements(ETSChecker *checker, ir::ScriptFunction *containing_func, checker::Type *&func_return_type,
                             ir::ReturnStatement *st, ir::Expression *st_argument)
{
    func_return_type = containing_func->Signature()->ReturnType();

    if (st_argument == nullptr) {
        // previous return statement(s) have value
        if (!func_return_type->IsETSVoidType() && func_return_type != checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    st->Start());
        }
    } else {
        //  previous return statement(s) don't have any value
        if (func_return_type->IsETSVoidType() || func_return_type == checker->GlobalBuiltinVoidType()) {
            checker->ThrowTypeError("All return statements in the function should be empty or have a value.",
                                    st_argument->Start());
        }

        const auto name = containing_func->Scope()->InternalName().Mutf8();
        if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
            if (func_return_type == checker->GlobalBuiltinVoidType()) {
                func_return_type = checker->GlobalVoidType();
            } else if (!func_return_type->IsETSVoidType() && !func_return_type->IsIntType()) {
                checker->ThrowTypeError("Bad return type, main enable only void or int type.", st->Start());
            }
        }

        if (st_argument->IsObjectExpression()) {
            st_argument->AsObjectExpression()->SetPreferredType(func_return_type);
        }

        if (st_argument->IsMemberExpression()) {
            checker->SetArrayPreferredTypeForNestedMemberExpressions(st_argument->AsMemberExpression(),
                                                                     func_return_type);
        }

        checker::Type *argument_type = st_argument->Check(checker);
        // remove CONSTANT type modifier if exists
        if (argument_type->HasTypeFlag(checker::TypeFlag::CONSTANT)) {
            argument_type =
                argument_type->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
            argument_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
        }

        auto *const relation = checker->Relation();
        relation->SetNode(st_argument);

        if (!relation->IsIdenticalTo(func_return_type, argument_type)) {
            if (func_return_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT) ||
                argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                // function return type should be of reference (object) type
                relation->SetFlags(checker::TypeRelationFlag::NONE);

                if (!argument_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                    argument_type = checker->PrimitiveTypeAsETSBuiltinType(argument_type);
                    if (argument_type == nullptr) {
                        checker->ThrowTypeError("Invalid return statement expression", st_argument->Start());
                    }
                    st_argument->AddBoxingUnboxingFlag(checker->GetBoxingFlag(argument_type));
                }

                if (!func_return_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
                    func_return_type = checker->PrimitiveTypeAsETSBuiltinType(func_return_type);
                    if (func_return_type == nullptr) {
                        checker->ThrowTypeError("Invalid return function expression", st->Start());
                    }
                }

                func_return_type = checker->FindLeastUpperBound(func_return_type, argument_type);
                containing_func->Signature()->SetReturnType(func_return_type);
                containing_func->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
            } else if (func_return_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN) &&
                       argument_type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE_RETURN)) {
                // function return type is of primitive type (including enums):
                relation->SetFlags(checker::TypeRelationFlag::DIRECT_RETURN |
                                   checker::TypeRelationFlag::IN_ASSIGNMENT_CONTEXT |
                                   checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
                if (relation->IsAssignableTo(func_return_type, argument_type)) {
                    func_return_type = argument_type;
                    containing_func->Signature()->SetReturnType(func_return_type);
                    containing_func->Signature()->AddSignatureFlag(checker::SignatureFlags::INFERRED_RETURN_TYPE);
                } else if (!relation->IsAssignableTo(argument_type, func_return_type)) {
                    checker->ThrowTypeError(
                        "Return statement type is not compatible with previous method's return statement "
                        "type(s).",
                        st_argument->Start());
                }
            } else {
                checker->ThrowTypeError("Invalid return statement type(s).", st->Start());
            }
        }

        relation->SetNode(nullptr);
        relation->SetFlags(checker::TypeRelationFlag::NONE);
    }
}

checker::Type *ETSAnalyzer::Check(ir::ReturnStatement *st) const
{
    ETSChecker *checker = GetETSChecker();

    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(st, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->IsConstructor()) {
        if (st->argument_ != nullptr) {
            checker->ThrowTypeError("Return statement with expression isn't allowed in constructor.", st->Start());
        }
        return nullptr;
    }

    ASSERT(containing_func->ReturnTypeAnnotation() != nullptr || containing_func->Signature()->ReturnType() != nullptr);

    checker::Type *func_return_type = nullptr;

    if (auto *const return_type_annotation = containing_func->ReturnTypeAnnotation();
        return_type_annotation != nullptr) {
        // Case when function's return type is defined explicitly:
        func_return_type = checker->GetTypeFromTypeAnnotation(return_type_annotation);

        if (st->argument_ == nullptr) {
            if (!func_return_type->IsETSVoidType() && func_return_type != checker->GlobalBuiltinVoidType()) {
                checker->ThrowTypeError("Missing return value.", st->Start());
            }
            func_return_type =
                containing_func->IsEntryPoint() ? checker->GlobalVoidType() : checker->GlobalBuiltinVoidType();
        } else {
            const auto name = containing_func->Scope()->InternalName().Mutf8();
            CheckArgumentVoidType(func_return_type, checker, name, st);

            if (st->argument_->IsObjectExpression()) {
                st->argument_->AsObjectExpression()->SetPreferredType(func_return_type);
            }
            if (st->argument_->IsMemberExpression()) {
                checker->SetArrayPreferredTypeForNestedMemberExpressions(st->argument_->AsMemberExpression(),
                                                                         func_return_type);
            }

            checker::Type *argument_type = st->argument_->Check(checker);

            CheckReturnType(checker, func_return_type, argument_type, st->argument_);
        }
    } else {
        //  Case when function's return type should be inferred from return statement(s):
        if (containing_func->Signature()->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
            InferReturnType(checker, containing_func, func_return_type, st->argument_);
        } else {
            //  All subsequent return statements:
            ProcessReturnStatements(checker, containing_func, func_return_type, st, st->argument_);
        }
    }

    if ((st->argument_ != nullptr) && st->argument_->IsArrayExpression()) {
        st->argument_->AsArrayExpression()->SetPreferredType(
            func_return_type->IsETSArrayType() ? func_return_type->AsETSArrayType()->ElementType() : func_return_type);
    }

    st->return_type_ = func_return_type;
    return nullptr;
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::SwitchStatement *st) const
{
    ETSChecker *checker = GetETSChecker();
    checker::ScopeContext scope_ctx(checker, st->scope_);
    st->discriminant_->Check(checker);
    checker::SavedTypeRelationFlagsContext saved_type_relation_flag_ctx(checker->Relation(),
                                                                        checker::TypeRelationFlag::NONE);
    // TODO(user): check exhaustive Switch
    checker->CheckSwitchDiscriminant(st->discriminant_);
    auto *compared_expr_type = st->discriminant_->TsType();
    auto unboxed_disc_type =
        (st->Discriminant()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U
            ? checker->ETSBuiltinTypeAsPrimitiveType(compared_expr_type)
            : compared_expr_type;

    bool valid_case_type;

    for (auto *it : st->Cases()) {
        if (it->Test() != nullptr) {
            auto *case_type = it->Test()->Check(checker);
            valid_case_type = true;
            if (case_type->HasTypeFlag(checker::TypeFlag::CHAR)) {
                valid_case_type = compared_expr_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL);
            } else if (case_type->IsETSEnumType() && st->Discriminant()->TsType()->IsETSEnumType()) {
                valid_case_type =
                    st->Discriminant()->TsType()->AsETSEnumType()->IsSameEnumType(case_type->AsETSEnumType());
            } else if (case_type->IsETSStringEnumType() && st->Discriminant()->TsType()->IsETSStringEnumType()) {
                valid_case_type = st->Discriminant()->TsType()->AsETSStringEnumType()->IsSameEnumType(
                    case_type->AsETSStringEnumType());
            } else {
                checker::AssignmentContext(
                    checker->Relation(), st->discriminant_, case_type, unboxed_disc_type, it->Test()->Start(),
                    {"Switch case type ", case_type, " is not comparable to discriminant type ", compared_expr_type},
                    (compared_expr_type->IsETSObjectType() ? checker::TypeRelationFlag::NO_WIDENING
                                                           : checker::TypeRelationFlag::NO_UNBOXING) |
                        checker::TypeRelationFlag::NO_BOXING);
            }

            if (!valid_case_type) {
                checker->ThrowTypeError(
                    {"Switch case type ", case_type, " is not comparable to discriminant type ", compared_expr_type},
                    it->Test()->Start());
            }
        }

        for (auto *case_stmt : it->Consequent()) {
            case_stmt->Check(checker);
        }
    }

    checker->CheckForSameSwitchCases(&st->cases_);

    return nullptr;
}

checker::Type *ETSAnalyzer::Check(ir::ThrowStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TryStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::VariableDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::WhileStatement *st) const
{
    (void)st;
    UNREACHABLE();
}
// from ts folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSAnyKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSArrayType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSBigintKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSBooleanKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSClassImplements *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSConditionalType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSConstructorType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSEnumDeclaration *st) const
{
    ETSChecker *checker = GetETSChecker();
    varbinder::Variable *enum_var = st->Key()->Variable();
    ASSERT(enum_var != nullptr);

    if (enum_var->TsType() == nullptr) {
        checker::Type *ets_enum_type;
        if (auto *const item_init = st->Members().front()->AsTSEnumMember()->Init(); item_init->IsNumberLiteral()) {
            ets_enum_type = checker->CreateETSEnumType(st);
        } else if (item_init->IsStringLiteral()) {
            ets_enum_type = checker->CreateETSStringEnumType(st);
        } else {
            checker->ThrowTypeError("Invalid enumeration value type.", st->Start());
        }
        st->SetTsType(ets_enum_type);
        ets_enum_type->SetVariable(enum_var);
        enum_var->SetTsType(ets_enum_type);
    } else if (st->TsType() == nullptr) {
        st->SetTsType(enum_var->TsType());
    }

    return st->TsType();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSEnumMember *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSExternalModuleReference *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSImportEqualsDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSImportType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSIndexedAccessType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSInferType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSInterfaceBody *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSInterfaceDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSInterfaceHeritage *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSIntersectionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSLiteralType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSMappedType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSModuleBlock *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSModuleDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSNamedTupleMember *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSNeverKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSNonNullExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSNullKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNumberKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSObjectKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSParameterProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSParenthesizedType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSQualifiedName *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSStringKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSThisType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTupleType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeAliasDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeAssertion *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeLiteral *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeOperator *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeParameter *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeParameterDeclaration *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeParameterInstantiation *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypePredicate *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeQuery *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSTypeReference *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUndefinedKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check(ir::TSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUnknownKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSVoidKeyword *node) const
{
    UNREACHABLE();
}

}  // namespace panda::es2panda::checker
