/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.Apache.Org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "helpers.h"

#include "binder/privateBinding.h"
#include "checker/types/ets/types.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/objectExpression.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/module/importSpecifier.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ts/tsParameterProperty.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/module/importDeclaration.h"
#include "lexer/token/letters.h"
#include <locale>
#include <codecvt>

namespace panda::es2panda::util {
// Helpers

bool Helpers::IsGlobalIdentifier(const util::StringView &str)
{
    return (str.Is("NaN") || str.Is("undefined") || str.Is("Infinity"));
}

bool Helpers::ContainSpreadElement(const ArenaVector<ir::Expression *> &args)
{
    return std::any_of(args.begin(), args.end(), [](const auto *it) { return it->IsSpreadElement(); });
}

util::StringView Helpers::LiteralToPropName(const ir::Expression *lit)
{
    switch (lit->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            return lit->AsIdentifier()->Name();
        }
        case ir::AstNodeType::STRING_LITERAL: {
            return lit->AsStringLiteral()->Str();
        }
        case ir::AstNodeType::NUMBER_LITERAL: {
            return lit->AsNumberLiteral()->Str();
        }
        case ir::AstNodeType::NULL_LITERAL: {
            return "null";
        }
        default: {
            UNREACHABLE();
        }
    }
}

bool Helpers::IsIndex(double number)
{
    if (number >= 0 && number < static_cast<double>(INVALID_INDEX)) {
        auto int_num = static_cast<uint32_t>(number);

        if (static_cast<double>(int_num) == number) {
            return true;
        }
    }

    return false;
}

static bool IsDigit(char c)
{
    return (c >= '0' && c <= '9');
}

int64_t Helpers::GetIndex(const util::StringView &str)
{
    const auto &s = str.Utf8();

    if (s.empty() || (*s.begin() == '0' && s.length() > 1)) {
        return INVALID_INDEX;
    }

    int64_t value = 0;
    for (const auto c : s) {
        if (!IsDigit(c)) {
            return INVALID_INDEX;
        }

        constexpr auto MULTIPLIER = 10;
        value *= MULTIPLIER;
        value += (c - '0');

        if (value >= INVALID_INDEX) {
            return INVALID_INDEX;
        }
    }

    return value;
}

std::string Helpers::ToString(double number)
{
    std::string str;

    if (Helpers::IsInteger<int32_t>(number)) {
        str = std::to_string(static_cast<int32_t>(number));
    } else {
        str = std::to_string(number);
    }

    return str;
}

util::StringView Helpers::ToStringView(ArenaAllocator *allocator, double number)
{
    util::UString str(ToString(number), allocator);
    return str.View();
}

util::StringView Helpers::ToStringView(ArenaAllocator *allocator, uint32_t number)
{
    ASSERT(number <= static_cast<uint32_t>(std::numeric_limits<int32_t>::max()));
    return ToStringView(allocator, static_cast<int32_t>(number));
}

util::StringView Helpers::ToStringView(ArenaAllocator *allocator, int32_t number)
{
    util::UString str(ToString(number), allocator);
    return str.View();
}

bool Helpers::IsRelativePath(const std::string &path)
{
    auto path_delimiter = panda::os::file::File::GetPathDelim();

    std::string current_dir_reference = ".";
    std::string parent_dir_reference = "..";

    current_dir_reference.append(path_delimiter);
    parent_dir_reference.append(path_delimiter);

    return ((path.find(current_dir_reference) == 0) || (path.find(parent_dir_reference) == 0));
}

const ir::ScriptFunction *Helpers::GetContainingConstructor(const ir::AstNode *node)
{
    const ir::ScriptFunction *iter = GetContainingFunction(node);

    while (iter != nullptr) {
        if (iter->IsConstructor()) {
            return iter;
        }

        if (!iter->IsArrow()) {
            return nullptr;
        }

        iter = GetContainingFunction(iter);
    }

    return iter;
}

const ir::TSEnumDeclaration *Helpers::GetContainingEnumDeclaration(const ir::AstNode *node)
{
    auto *iter = node;

    while (iter != nullptr) {
        if (iter->IsTSEnumDeclaration()) {
            return iter->AsTSEnumDeclaration();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const checker::ETSObjectType *Helpers::GetContainingObjectType(const ir::AstNode *node)
{
    const auto *iter = node;

    while (iter != nullptr) {
        if (iter->IsClassDefinition()) {
            auto *ret = iter->AsClassDefinition()->TsType();
            return ret != nullptr ? ret->AsETSObjectType() : nullptr;
        }

        if (iter->IsTSInterfaceDeclaration()) {
            auto *ret = iter->AsTSInterfaceDeclaration()->TsType();
            return ret != nullptr ? ret->AsETSObjectType() : nullptr;
        }

        if (iter->IsTSEnumDeclaration()) {
            auto *ret = iter->AsTSEnumDeclaration()->TsType();
            return ret != nullptr ? ret->AsETSObjectType() : nullptr;
        }

        if (iter->IsImportDeclaration()) {
            // return iter->AsImportDeclaration();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const ir::ClassDefinition *Helpers::GetContainingClassDefinition(const ir::AstNode *node)
{
    const auto *iter = node;

    while (iter != nullptr) {
        if (iter->IsClassDefinition()) {
            return iter->AsClassDefinition();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const ir::TSInterfaceDeclaration *Helpers::GetContainingInterfaceDeclaration(const ir::AstNode *node)
{
    const auto *iter = node;

    while (iter != nullptr) {
        if (iter->IsTSInterfaceDeclaration()) {
            return iter->AsTSInterfaceDeclaration();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const ir::MethodDefinition *Helpers::GetContainingClassMethodDefinition(const ir::AstNode *node)
{
    const auto *iter = node;

    while (iter != nullptr) {
        if (iter->IsMethodDefinition()) {
            return iter->AsMethodDefinition();
        }

        if (iter->IsClassDefinition()) {
            break;
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const ir::ClassStaticBlock *Helpers::GetContainingClassStaticBlock(const ir::AstNode *node)
{
    const auto *iter = node;

    while (iter != nullptr) {
        if (iter->IsClassStaticBlock()) {
            return iter->AsClassStaticBlock();
        }

        if (iter->IsClassDefinition()) {
            break;
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const ir::ScriptFunction *Helpers::GetContainingConstructor(const ir::ClassProperty *node)
{
    for (const auto *parent = node->Parent(); parent != nullptr; parent = parent->Parent()) {
        if (parent->IsClassDefinition()) {
            return parent->AsClassDefinition()->Ctor()->Function();
        }
    }

    return nullptr;
}

const ir::ScriptFunction *Helpers::GetContainingFunction(const ir::AstNode *node)
{
    for (const auto *parent = node->Parent(); parent != nullptr; parent = parent->Parent()) {
        if (parent->IsScriptFunction()) {
            return parent->AsScriptFunction();
        }
    }

    return nullptr;
}

ir::AstNode *Helpers::FindAncestorGivenByType(ir::AstNode *node, ir::AstNodeType type)
{
    node = node->Parent();

    while (node->Type() != type) {
        if (node->Parent() != nullptr) {
            node = node->Parent();
            continue;
        }

        return nullptr;
    }

    return node;
}

const ir::ClassDefinition *Helpers::GetClassDefiniton(const ir::ScriptFunction *node)
{
    ASSERT(node->IsConstructor());
    ASSERT(node->Parent()->IsFunctionExpression());
    ASSERT(node->Parent()->Parent()->IsMethodDefinition());
    ASSERT(node->Parent()->Parent()->Parent()->IsClassDefinition());

    return node->Parent()->Parent()->Parent()->AsClassDefinition();
}

bool Helpers::IsSpecialPropertyKey(const ir::Expression *expr)
{
    if (!expr->IsStringLiteral()) {
        return false;
    }

    auto *lit = expr->AsStringLiteral();
    return lit->Str().Is("prototype") || lit->Str().Is("constructor");
}

bool Helpers::IsConstantPropertyKey(const ir::Expression *expr, bool is_computed)
{
    switch (expr->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            return !is_computed;
        }
        case ir::AstNodeType::NUMBER_LITERAL:
        case ir::AstNodeType::STRING_LITERAL:
        case ir::AstNodeType::BOOLEAN_LITERAL:
        case ir::AstNodeType::NULL_LITERAL: {
            return true;
        }
        default:
            break;
    }

    return false;
}

compiler::Literal Helpers::ToConstantLiteral(const ir::Expression *expr)
{
    switch (expr->Type()) {
        case ir::AstNodeType::NUMBER_LITERAL: {
            auto *lit = expr->AsNumberLiteral();
            if (util::Helpers::IsInteger<uint32_t>(lit->Number().GetDouble())) {
                return compiler::Literal(static_cast<uint32_t>(lit->Number().GetDouble()));
            }
            return compiler::Literal(lit->Number().GetDouble());
        }
        case ir::AstNodeType::STRING_LITERAL: {
            auto *lit = expr->AsStringLiteral();
            return compiler::Literal(lit->Str());
        }
        case ir::AstNodeType::BOOLEAN_LITERAL: {
            auto *lit = expr->AsBooleanLiteral();
            return compiler::Literal(lit->Value());
        }
        case ir::AstNodeType::NULL_LITERAL: {
            return compiler::Literal::NullLiteral();
        }
        default:
            break;
    }

    return compiler::Literal();
}

bool Helpers::IsBindingPattern(const ir::AstNode *node)
{
    return node->IsArrayPattern() || node->IsObjectPattern();
}

bool Helpers::IsPattern(const ir::AstNode *node)
{
    return node->IsArrayPattern() || node->IsObjectPattern() || node->IsAssignmentPattern();
}

static void CollectBindingName(ir::AstNode *node, std::vector<ir::Identifier *> *bindings)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            if (!Helpers::IsGlobalIdentifier(node->AsIdentifier()->Name())) {
                bindings->push_back(node->AsIdentifier());
            }

            break;
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            for (auto *prop : node->AsObjectPattern()->Properties()) {
                CollectBindingName(prop, bindings);
            }
            break;
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            for (auto *element : node->AsArrayPattern()->Elements()) {
                CollectBindingName(element, bindings);
            }
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            CollectBindingName(node->AsAssignmentPattern()->Left(), bindings);
            break;
        }
        case ir::AstNodeType::PROPERTY: {
            CollectBindingName(node->AsProperty()->Value(), bindings);
            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            CollectBindingName(node->AsRestElement()->Argument(), bindings);
            break;
        }
        default:
            break;
    }
}

std::vector<ir::Identifier *> Helpers::CollectBindingNames(ir::AstNode *node)
{
    std::vector<ir::Identifier *> bindings;
    CollectBindingName(node, &bindings);
    return bindings;
}

void Helpers::CheckImportedName(ArenaVector<ir::AstNode *> *specifiers, const ir::ImportSpecifier *specifier,
                                const std::string &file_name)
{
    auto new_ident_name = specifier->Imported()->Name();
    auto new_alias_name = specifier->Local()->Name();
    std::stringstream message {};

    for (auto *it : *specifiers) {
        if (!it->IsImportSpecifier()) {
            continue;
        }

        auto saved_ident_name = it->AsImportSpecifier()->Imported()->Name();
        auto saved_alias_name = it->AsImportSpecifier()->Local()->Name();

        if (saved_ident_name == saved_alias_name && saved_alias_name == new_ident_name) {
            message << "Warning: '" << new_ident_name << "' has already imported ";
            break;
        }
        if (saved_ident_name == new_ident_name && new_alias_name != saved_alias_name) {
            message << "Warning: '" << new_ident_name << "' is explicitly used with alias several times ";
            break;
        }
    }

    if (message.rdbuf()->in_avail() > 0) {
        std::cerr << message.str() << "[" << file_name.c_str() << ":" << specifier->Start().line << ":"
                  << specifier->Start().index << "]" << std::endl;
    }
}

util::StringView Helpers::FunctionName(ArenaAllocator *allocator, const ir::ScriptFunction *func)
{
    if (func->Id() != nullptr) {
        return func->Id()->Name();
    }

    if (func->Parent()->IsFunctionDeclaration()) {
        return "*default*";
    }

    const ir::AstNode *parent = func->Parent()->Parent();

    if (func->IsConstructor()) {
        parent = parent->Parent();
        if (parent->AsClassDefinition()->Ident() != nullptr) {
            return parent->AsClassDefinition()->Ident()->Name();
        }

        parent = parent->Parent()->Parent();
    }

    switch (parent->Type()) {
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            const ir::VariableDeclarator *var_decl = parent->AsVariableDeclarator();

            if (var_decl->Id()->IsIdentifier()) {
                return var_decl->Id()->AsIdentifier()->Name();
            }

            break;
        }
        case ir::AstNodeType::METHOD_DEFINITION: {
            const ir::MethodDefinition *method_def = parent->AsMethodDefinition();

            if (method_def->Key()->IsIdentifier()) {
                auto *ident = method_def->Id();

                if (!ident->IsPrivateIdent()) {
                    return ident->Name();
                }

                return util::UString(binder::PrivateBinding::ToPrivateBinding(ident->Name()), allocator).View();
            }

            break;
        }
        case ir::AstNodeType::ASSIGNMENT_EXPRESSION: {
            const ir::AssignmentExpression *assignment = parent->AsAssignmentExpression();

            if (assignment->Left()->IsIdentifier()) {
                return assignment->Left()->AsIdentifier()->Name();
            }

            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            const ir::AssignmentExpression *assignment = parent->AsAssignmentPattern();

            if (assignment->Left()->IsIdentifier()) {
                return assignment->Left()->AsIdentifier()->Name();
            }

            break;
        }
        case ir::AstNodeType::PROPERTY: {
            const ir::Property *prop = parent->AsProperty();

            if (prop->Kind() != ir::PropertyKind::PROTO &&
                Helpers::IsConstantPropertyKey(prop->Key(), prop->IsComputed())) {
                return Helpers::LiteralToPropName(prop->Key());
            }

            break;
        }
        default:
            break;
    }

    return util::StringView();
}

std::tuple<util::StringView, bool> Helpers::ParamName(ArenaAllocator *allocator, const ir::AstNode *param,
                                                      uint32_t index)
{
    switch (param->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            return {param->AsIdentifier()->Name(), false};
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            const auto *lhs = param->AsAssignmentPattern()->Left();
            if (lhs->IsIdentifier()) {
                return {param->AsAssignmentPattern()->Left()->AsIdentifier()->Name(), false};
            }
            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            if (param->AsRestElement()->Argument()->IsIdentifier()) {
                return {param->AsRestElement()->Argument()->AsIdentifier()->Name(), false};
            }
            break;
        }
        case ir::AstNodeType::TS_PARAMETER_PROPERTY: {
            return ParamName(allocator, param->AsTSParameterProperty()->Parameter(), index);
        }
        case ir::AstNodeType::ETS_PARAMETER_EXPRESSION: {
            return {param->AsETSParameterExpression()->Ident()->Name(), false};
        }
        default:
            break;
    }

    return {Helpers::ToStringView(allocator, index), true};
}

std::string Helpers::CreateEscapedString(const std::string &str)
{
    std::string ret {};
    ret.reserve(str.size());

    for (std::string::value_type c : str) {
        switch (c) {
            case lexer::LEX_CHAR_BS: {
                ret.append("\\b");
                break;
            }
            case lexer::LEX_CHAR_TAB: {
                ret.append("\\t");
                break;
            }
            case lexer::LEX_CHAR_LF: {
                ret.append("\\n");
                break;
            }
            case lexer::LEX_CHAR_VT: {
                ret.append("\\v");
                break;
            }
            case lexer::LEX_CHAR_FF: {
                ret.append("\\f");
                break;
            }
            case lexer::LEX_CHAR_CR: {
                ret.append("\\r");
                break;
            }
            default: {
                ret += c;
                break;
            }
        }
    }

    return ret;
}

std::string Helpers::UTF16toUTF8(const char16_t c)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert {};
    return convert.to_bytes(c);
}

template <class F>
static const ir::ETSImportDeclaration *ImportDeclarationForDynamicVarInternal(const binder::Variable *var, F pred)
{
    auto *decl_node = var->Declaration()->Node();
    if (!decl_node) {
        return nullptr;
    }

    if (!decl_node->IsImportNamespaceSpecifier() && !decl_node->IsImportSpecifier()) {
        return nullptr;
    }

    if (!pred(decl_node)) {
        return nullptr;
    }

    auto *parent = decl_node->Parent();
    if (!parent || !parent->IsETSImportDeclaration()) {
        return nullptr;
    }

    return parent->AsETSImportDeclaration();
}

bool Helpers::IsDynamicModuleVariable(const binder::Variable *var)
{
    auto *import = ImportDeclarationForDynamicVarInternal(
        var, [](const ir::AstNode *decl_node) { return decl_node->IsImportSpecifier(); });
    if (import == nullptr) {
        return false;
    }
    return import->IsPureDynamic();
}

bool Helpers::IsDynamicNamespaceVariable(const binder::Variable *var)
{
    auto *import = ImportDeclarationForDynamicVarInternal(
        var, [](const ir::AstNode *decl_node) { return decl_node->IsImportNamespaceSpecifier(); });
    if (import == nullptr) {
        return false;
    }
    return import->IsPureDynamic();
}

const ir::ETSImportDeclaration *Helpers::ImportDeclarationForDynamicVar(const binder::Variable *var)
{
    return ImportDeclarationForDynamicVarInternal(var, [](const ir::AstNode *) { return true; });
}

std::pair<std::string_view, std::string_view> Helpers::SplitSignature(std::string_view signature)
{
    auto idx = signature.find_last_of(':');
    auto stripped = signature.substr(0, idx);
    idx = stripped.find_last_of('.');
    auto full_class_name = stripped.substr(0, idx);
    auto method_name = stripped.substr(idx + 1);
    idx = full_class_name.find_last_of('.');
    auto class_name = full_class_name.substr(idx + 1);
    return {class_name, method_name};
}

}  // namespace panda::es2panda::util
