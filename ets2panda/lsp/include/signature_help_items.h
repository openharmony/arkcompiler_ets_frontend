/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_LSP_INCLUDE_SIGNATURE_HELP_ITEMS_H
#define ES2PANDA_LSP_INCLUDE_SIGNATURE_HELP_ITEMS_H

#include <cstddef>
#include "create_type_help_items.h"

namespace ark::es2panda::lsp {

inline constexpr std::string_view const GENSYM_CORE = "gensym%%_";
inline constexpr std::string_view const DUMMY_ID = "_";

struct ArgumentListInfo {
private:
    TextSpan applicableSpan_ {0, 0};
    uint32_t argumentCount_ {0};
    size_t argumentIndex_ {0};

public:
    void SetApplicableSpan(TextSpan &applicableSpan)
    {
        applicableSpan_ = applicableSpan;
    }

    void SetArgumentCount(uint32_t argumentCount)
    {
        argumentCount_ = argumentCount;
    }

    void SetArgumentIndex(size_t argumentIndex)
    {
        argumentIndex_ = argumentIndex;
    }

    TextSpan GetApplicableSpan()
    {
        return applicableSpan_;
    }

    uint32_t GetArgumentCount()
    {
        return argumentCount_;
    }

    size_t GetArgumentIndex()
    {
        return argumentIndex_;
    }
};

SignatureHelpItems CreateSignatureHelpItems(ArenaAllocator *allocator, ArenaVector<checker::Signature *> &signatures,
                                            checker::Signature &signature, ArgumentListInfo &argumentListInfo);

ArenaVector<SignatureHelpItem> GetSignatureHelpItem(ArenaAllocator *allocator,
                                                    ArenaVector<checker::Signature *> &signatures);

SignatureHelpItem CreateSignatureHelpItem(ArenaAllocator *allocator, checker::Signature &signature);

void SetSignatureHelpParameter(ArenaAllocator *allocator, const checker::SignatureInfo *signatureInfo,
                               SignatureHelpItem &signatureHelpItem);

}  // namespace ark::es2panda::lsp

#endif  // ES2PANDA_LSP_INCLUDE_SIGNATURE_HELP_ITEMS_H