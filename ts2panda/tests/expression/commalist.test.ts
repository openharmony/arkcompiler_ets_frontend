/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
    expect
} from 'chai';
import 'mocha';
import {
    Returnundefined,
    Stglobalvar,
    Tryldglobalbyname,
    Imm,
    Lda,
    Mov,
    Sta,
    Defineclasswithbuffer,
    Sttoglobalrecord,
    Newobjrange,
    VReg,
    IRNode
} from "../../src/irnodes";
import { checkInstructions, SnippetCompiler } from "../utils/base";
import { creatAstFromSnippet } from "../utils/asthelper"
import { PandaGen } from '../../src/pandagen';

describe("CommaListExpression", function () {
    it("computedPropertyName", function () {
        let snippetCompiler = new SnippetCompiler();
        snippetCompiler.compileAfter(" \
        class Test { \
            #filed1; \
            #filed2; \
            #filed3; \
            #filed4; \
            #filed5; \
            #filed6; \
            #filed7; \
            #filed8; \
            #filed9; \
            #filed10; \
            #filed11; \
        } \
        ",
        "test.ts");
        IRNode.pg = new PandaGen("foo", creatAstFromSnippet(" \
        class Test { \
            #filed1; \
            #filed2; \
            #filed3; \
            #filed4; \
            #filed5; \
            #filed6; \
            #filed7; \
            #filed8; \
            #filed9; \
            #filed10; \
            #filed11; \
        } \
        "), 0, undefined);
        let insns = snippetCompiler.getGlobalInsns();
        let expected = [
            new Mov(new VReg(), new VReg()),
            new Defineclasswithbuffer(new Imm(0), "UnitTest.#1#Test", "_0", new Imm(0), new VReg()),
            new Sta(new VReg()),
            new Lda(new VReg()),
            new Sttoglobalrecord(new Imm(1), "Test"),
            new Tryldglobalbyname(new Imm(2), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(3), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(4), '_Test_filed1'),
            new Tryldglobalbyname(new Imm(5), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(6), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(7), '_Test_filed2'),
            new Tryldglobalbyname(new Imm(8), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(9), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(10), '_Test_filed3'),
            new Tryldglobalbyname(new Imm(11), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(12), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(13), '_Test_filed4'),
            new Tryldglobalbyname(new Imm(14), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(15), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(16), '_Test_filed5'),
            new Tryldglobalbyname(new Imm(17), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(18), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(19), '_Test_filed6'),
            new Tryldglobalbyname(new Imm(20), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(21), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(22), '_Test_filed7'),
            new Tryldglobalbyname(new Imm(23), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(24), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(25), '_Test_filed8'),
            new Tryldglobalbyname(new Imm(26), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(27), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(28), '_Test_filed9'),
            new Tryldglobalbyname(new Imm(29), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(30), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(31), '_Test_filed10'),
            new Tryldglobalbyname(new Imm(32), 'WeakMap'),
            new Sta(new VReg()),
            new Newobjrange(new Imm(33), new Imm(1), [new VReg()]),
            new Stglobalvar(new Imm(34), '_Test_filed11'),
            new Returnundefined()
        ]
        expect(checkInstructions(insns, expected)).to.be.true;
    });

});
