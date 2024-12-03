/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

namespace ark::es2panda::checker {

// from as folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NamedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::Decorator *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::MetaProperty *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ScriptFunction *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSIndexSignature *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSMethodSignature *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSPropertySignature *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSSignatureDeclaration *node) const
{
    UNREACHABLE();
}
// from ets folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSScript *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSImportDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSTuple *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSUnionType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSWildcardType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ChainExpression *expr) const
{
    UNREACHABLE();  // eliminated in OptionalLowering
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ClassExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ETSReExportDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::DirectEvalExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::FunctionExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::NewExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::OmittedExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TaggedTemplateExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::YieldExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::RegExpLiteral *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::UndefinedLiteral *expr) const
{
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportAllDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportDefaultDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportNamedDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ExportSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportDefaultSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ImportSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::DebuggerStatement *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::ForInStatement *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::FunctionDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

// from ts folder
checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSAnyKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSBigintKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSBooleanKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSClassImplements *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSConditionalType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSConstructorType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSEnumMember *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSExternalModuleReference *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSFunctionType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSImportEqualsDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSImportType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSIndexedAccessType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSInferType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSInterfaceBody *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSInterfaceHeritage *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSIntersectionType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSLiteralType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSMappedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSModuleBlock *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSModuleDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNamedTupleMember *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNeverKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSNullKeyword *node) const
{
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

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSParameterProperty *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSParenthesizedType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSStringKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSThisType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTupleType *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeAssertion *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeLiteral *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeOperator *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameter *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterInstantiation *expr) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypePredicate *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeQuery *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSTypeReference *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUndefinedKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::TSUnionType *node) const
{
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

checker::Type *ETSAnalyzer::Check([[maybe_unused]] ir::DummyNode *expr) const
{
    UNREACHABLE();
}
}  // namespace ark::es2panda::checker
