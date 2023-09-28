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

#include "property.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrayExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/validationInfo.h"

namespace panda::es2panda::ir {
bool Property::ConvertibleToPatternProperty()
{
    // Object pattern can't contain getter or setter
    if (IsAccessor() || is_method_) {
        return false;
    }

    switch (value_->Type()) {
        case AstNodeType::OBJECT_EXPRESSION: {
            return value_->AsObjectExpression()->ConvertibleToObjectPattern();
        }
        case AstNodeType::ARRAY_EXPRESSION: {
            return value_->AsArrayExpression()->ConvertibleToArrayPattern();
        }
        case AstNodeType::ASSIGNMENT_EXPRESSION: {
            return value_->AsAssignmentExpression()->ConvertibleToAssignmentPattern();
        }
        case AstNodeType::IDENTIFIER:
        case AstNodeType::MEMBER_EXPRESSION:
        case AstNodeType::ARRAY_PATTERN:
        case AstNodeType::OBJECT_PATTERN:
        case AstNodeType::ASSIGNMENT_PATTERN: {
            break;
        }
        default: {
            if (is_shorthand_) {
                break;
            }

            return false;
        }
    }

    return true;
}

ValidationInfo Property::ValidateExpression()
{
    ValidationInfo info;

    if (!IsComputed() && !IsMethod() && !IsAccessor() && !IsShorthand()) {
        bool current_is_proto = false;

        if (key_->IsIdentifier()) {
            current_is_proto = key_->AsIdentifier()->Name().Is("__proto__");
        } else if (key_->IsStringLiteral()) {
            current_is_proto = key_->AsStringLiteral()->Str().Is("__proto__");
        }

        if (current_is_proto) {
            kind_ = PropertyKind::PROTO;
        }
    }

    if (value_ != nullptr) {
        if (value_->IsAssignmentPattern()) {
            return {"Invalid shorthand property initializer.", value_->Start()};
        }

        if (value_->IsObjectExpression()) {
            info = value_->AsObjectExpression()->ValidateExpression();
        } else if (value_->IsArrayExpression()) {
            info = value_->AsArrayExpression()->ValidateExpression();
        }
    }

    return info;
}

void Property::Iterate(const NodeTraverser &cb) const
{
    cb(key_);
    cb(value_);
}

void Property::Dump(ir::AstDumper *dumper) const
{
    const char *kind = nullptr;

    switch (kind_) {
        case PropertyKind::INIT: {
            kind = "init";
            break;
        }
        case PropertyKind::PROTO: {
            kind = "proto";
            break;
        }
        case PropertyKind::GET: {
            kind = "get";
            break;
        }
        case PropertyKind::SET: {
            kind = "set";
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    dumper->Add({{"type", "Property"},
                 {"method", is_method_},
                 {"shorthand", is_shorthand_},
                 {"computed", is_computed_},
                 {"key", key_},
                 {"value", value_},
                 {"kind", kind}});
}

void Property::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *Property::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *Property::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
