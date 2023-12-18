/**
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#include "ETSchecker.h"

namespace ark::es2panda::checker {

CheckerContext::CheckerContext(Checker *checker, CheckerStatus newStatus, ETSObjectType const *containingClass,
                               Signature *containingSignature)
    : parent_(checker),
      status_(newStatus),
      capturedVars_(parent_->Allocator()->Adapter()),
      smartCasts_(parent_->Allocator()->Adapter()),
      containingClass_(containingClass),
      containingSignature_(containingSignature)
{
}

SmartCastArray CheckerContext::CloneSmartCasts(bool const clearData) noexcept
{
    SmartCastArray smartCasts {};

    if (!smartCasts_.empty()) {
        smartCasts.reserve(smartCasts_.size());

        for (auto const [variable, type] : smartCasts_) {
            smartCasts.emplace_back(variable, type);
        }
    }

    if (clearData) {
        ClearSmartCasts();
    }

    return smartCasts;
}

void CheckerContext::RestoreSmartCasts(SmartCastArray const &prevSmartCasts) noexcept
{
    smartCasts_.clear();
    if (!prevSmartCasts.empty()) {
        for (auto [variable, type] : prevSmartCasts) {
            smartCasts_.emplace(variable, type);
        }
    }
}

void CheckerContext::RemoveSmartCasts(SmartCastArray const &otherSmartCasts) noexcept
{
    if (!smartCasts_.empty()) {
        auto it = smartCasts_.begin();
        while (it != smartCasts_.end()) {
            if (std::find_if(otherSmartCasts.begin(), otherSmartCasts.end(), [&it](auto const &item) -> bool {
                    return item.first == it->first;
                }) == otherSmartCasts.end()) {
                it = smartCasts_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

checker::Type *CheckerContext::CombineTypes(checker::Type *const typeOne, checker::Type *const typeTwo) const noexcept
{
    ASSERT(typeOne != nullptr && typeTwo != nullptr);
    auto *const checker = parent_->AsETSChecker();

    if (checker->Relation()->IsIdenticalTo(typeOne, typeTwo)) {
        // no type change is required
        return nullptr;
    }

    return checker->CreateETSUnionType({typeOne, typeTwo});
}

void CheckerContext::CombineSmartCasts(SmartCastArray &alternateSmartCasts) noexcept
{
    auto *const checker = parent_->AsETSChecker();

    auto smartCast = alternateSmartCasts.begin();
    while (smartCast != alternateSmartCasts.end()) {
        auto const currentCast = smartCasts_.find(smartCast->first);
        if (currentCast == smartCasts_.end()) {
            // Remove smart cast that doesn't present in the current set.
            smartCast = alternateSmartCasts.erase(smartCast);
            continue;
        }

        // Smart type was modified
        if (auto *const smartType = CombineTypes(smartCast->second, currentCast->second); smartType != nullptr) {
            // Remove it or set to new value
            if (checker->Relation()->IsIdenticalTo(currentCast->first->TsType(), smartType)) {
                smartCasts_.erase(currentCast);
                smartCast = alternateSmartCasts.erase(smartCast);
                continue;
            }

            currentCast->second = smartType;
        }
        ++smartCast;
    }

    // Remove smart casts that don't present in the alternate set.
    RemoveSmartCasts(alternateSmartCasts);
}

void CheckerContext::AddSmartCasts(SmartCastArray const &initSmartCasts) noexcept
{
    auto *const checker = parent_->AsETSChecker();

    for (auto [variable, type] : initSmartCasts) {
        auto const currentCast = smartCasts_.find(variable);
        if (currentCast == smartCasts_.end()) {
            // Add smart casts that were not modified in the block.
            SetSmartCast(variable, type);
        } else if (auto *const smartType = CombineTypes(type, currentCast->second); smartType != nullptr) {
            // Smart type was modified: remove it or set to new value
            if (checker->Relation()->IsIdenticalTo(variable->TsType(), smartType)) {
                smartCasts_.erase(currentCast);
            } else {
                currentCast->second = smartType;
            }
        }
    }

    // Remove smart casts that don't present in the initial set.
    RemoveSmartCasts(initSmartCasts);
}

// Second return value shows if the 'IN_LOOP' flag should be cleared on exit from the loop (case of nested loops).
std::pair<SmartCastArray, bool> CheckerContext::EnterLoop() noexcept
{
    bool const clearFlag = !IsInLoop();
    if (clearFlag) {
        status_ |= CheckerStatus::IN_LOOP;
    }

    return {CloneSmartCasts(true), clearFlag};
}

void CheckerContext::ExitLoop(SmartCastArray const &prevSmartCasts, bool const clearFlag) noexcept
{
    if (clearFlag) {
        status_ &= ~CheckerStatus::IN_LOOP;
    }

    //  Now we don't process smart casts inside the loops correctly, thus just combine them on exit from the loop.
    AddSmartCasts(prevSmartCasts);
}

}  // namespace ark::es2panda::checker
