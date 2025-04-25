/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_LOWERING_PHASE_H
#define ES2PANDA_COMPILER_LOWERING_PHASE_H

#include "parser/program/program.h"
#include "public/public.h"

namespace ark::es2panda::compiler {

constexpr int32_t INVALID_PHASE_ID = -2;
constexpr int32_t PARSER_PHASE_ID = -1;

class Phase {
public:
    /* If Apply returns false, processing is stopped. */
    bool Apply(public_lib::Context *ctx, parser::Program *program);

    virtual std::string_view Name() const = 0;

    virtual bool Precondition([[maybe_unused]] public_lib::Context *ctx,
                              [[maybe_unused]] const parser::Program *program)
    {
        return true;
    }
    virtual bool Perform(public_lib::Context *ctx, parser::Program *program) = 0;
    virtual bool Postcondition([[maybe_unused]] public_lib::Context *ctx,
                               [[maybe_unused]] const parser::Program *program)
    {
        return true;
    }

private:
    friend class PhaseManager;
    int32_t id_ {INVALID_PHASE_ID};
};

/* Phase that modifies declarations. Need to process external dependencies */
class PhaseForDeclarations : public Phase {
    bool Precondition(public_lib::Context *ctx, const parser::Program *program) override;
    bool Perform(public_lib::Context *ctx, parser::Program *program) override;
    bool Postcondition(public_lib::Context *ctx, const parser::Program *program) override;

    /* Called from Perform, Pre/Postcondition */
    virtual bool PreconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                       [[maybe_unused]] const parser::Program *program)
    {
        return true;
    }
    virtual bool PerformForModule(public_lib::Context *ctx, parser::Program *program) = 0;
    virtual bool PostconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                        [[maybe_unused]] const parser::Program *program)
    {
        return true;
    }
};

/* Phase that only modifies bodies.
   No need to process external dependencies unless we are compiling stdlib.
*/
class PhaseForBodies : public Phase {
    bool Precondition(public_lib::Context *ctx, const parser::Program *program) override;
    bool Perform(public_lib::Context *ctx, parser::Program *program) override;
    bool Postcondition(public_lib::Context *ctx, const parser::Program *program) override;

    /* Called from Perform, Pre/Postcondition */
    virtual bool PreconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                       [[maybe_unused]] const parser::Program *program)
    {
        return true;
    }
    virtual bool PerformForModule(public_lib::Context *ctx, parser::Program *program) = 0;
    virtual bool PostconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                        [[maybe_unused]] const parser::Program *program)
    {
        return true;
    }
};

class PhaseManager {
public:
    PhaseManager(ScriptExtension ext, ArenaAllocator *allocator) : allocator_ {allocator}, ext_ {ext}
    {
        InitializePhases();
        Restart();
    }

    int32_t PreviousPhaseId() const
    {
        return prev_;
    }

    int32_t CurrentPhaseId() const
    {
        return curr_;
    }

    void SetCurrentPhaseId(int32_t phaseId)
    {
        prev_ = curr_;
        curr_ = phaseId;
    }

    ArenaAllocator *Allocator() const
    {
        return allocator_;
    }

    bool IsInitialized() const
    {
        return allocator_ != nullptr && ext_ != ScriptExtension::INVALID;
    }

    void Restart()
    {
        prev_ = INVALID_PHASE_ID;
        curr_ = PARSER_PHASE_ID;
        next_ = PARSER_PHASE_ID + 1;
        ES2PANDA_ASSERT(next_ == 0);
    }

    Phase *NextPhase()
    {
        if (next_ < static_cast<int32_t>(phases_.size())) {
            return phases_[next_++];
        }
        return nullptr;
    }

    std::vector<Phase *> AllPhases();
    std::vector<Phase *> RebindPhases();
    std::vector<Phase *> RecheckPhases();

private:
    void InitializePhases();
    int32_t prev_ {INVALID_PHASE_ID};
    int32_t curr_ {INVALID_PHASE_ID};
    int32_t next_ {INVALID_PHASE_ID};

    ArenaAllocator *allocator_ {nullptr};
    ScriptExtension ext_ {ScriptExtension::INVALID};
    std::vector<Phase *> phases_;
};

PhaseManager *GetPhaseManager();
void SetPhaseManager(PhaseManager *phaseManager);

}  // namespace ark::es2panda::compiler

#endif
