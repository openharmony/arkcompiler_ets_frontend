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

import { expect } from 'chai';
import 'mocha';
import * as ts from "typescript";
import {
    Callrange,
    Returnundefined,
    Sttoglobalrecord,
    Tryldglobalbyname,
    Imm,
    IRNode,
    Ldai,
    Lda,
    Sta,
    VReg
} from "../src/irnodes";
import { PandaGen } from "../src/pandagen";
import { CacheExpander } from "../src/pass/cacheExpander";
import { RegAlloc } from "../src/regAllocator";
import { basicChecker, checkInstructions, compileAllSnippet } from "./utils/base";
import { creatAstFromSnippet } from "./utils/asthelper";

function checkRegisterNumber(left: IRNode, right: IRNode): boolean {
    if (!basicChecker(left, right)) {
        return false;
    }
    let lo = left.operands;
    let ro = right.operands;
    if (lo.length !== ro.length) {
        return false;
    }
    for (let i = 0; i < lo.length; ++i) {
        let l = lo[i];
        let r = ro[i];
        if (l instanceof VReg && r instanceof VReg) {
            if (!((<VReg>l).num == (<VReg>r).num)) {
                return false;
            }
        }
    }
    return true;
}
describe("RegAllocator", function () {
    it("make spill for Src register", function () {
        let string: string = "";
        for (let i = 0; i < 256; ++i) {
            string += "let a" + i + " = " + i + ";";
        }
        string += "a255;";

        let pgs = compileAllSnippet(string, [new CacheExpander(), new RegAlloc()]);
        let insns = pgs[0].getInsns();
        IRNode.pg = new PandaGen("", creatAstFromSnippet(""), 0, undefined);
        IRNode.pg.updateIcSize(252);

        let expected: IRNode[] = [
            new Ldai(new Imm(252)),
            new Sttoglobalrecord(new Imm(0), 'a252'),
            new Ldai(new Imm(253)),
            new Sttoglobalrecord(new Imm(1), 'a253'),
            new Ldai(new Imm(254)),
            new Sttoglobalrecord(new Imm(2), 'a254'),
            new Ldai(new Imm(255)),
            new Sttoglobalrecord(new Imm(3), 'a255'),
            new Tryldglobalbyname(new Imm(4), 'a255'),
            new Returnundefined()
        ]

        expect(checkInstructions(insns.slice(insns.length - 10), expected, checkRegisterNumber)).to.be.true;
    });

    it("make spill for SrcDst register", function () {
        /* the only possible instruction whose operand register type could be SrcDstVReg is INCI,
         * but we do not use it at all by now
         */
        expect(true).to.be.true;
    });

    it("make spill for CalliRange", function () {
        /* since the bitwidth for CalliRange source register is 16 now, we do not need to make spill at all.
           but in case later 16 might be changed to 8, then spill operation will be needed in some cases. this testcase is designed
           for 8bits constraints.
        */
        let string = "";
        for (let i = 0; i < 256; ++i) {
            string += "let a" + i + " = " + i + ";";
        }
        string += "call(a252, a253, a254, a255);";
        let pgs = compileAllSnippet(string, [new CacheExpander(), new RegAlloc()]);
        let insns = pgs[0].getInsns();
        IRNode.pg = new PandaGen("", creatAstFromSnippet(""), 0, undefined);
        IRNode.pg.updateIcSize(252);
        let v = [];
        for (let i = 0; i < 8; ++i) {
            v[i] = new VReg();
            v[i].num = i;
        }
        let expected = [
            new Ldai(new Imm(252)),
            new Sttoglobalrecord(new Imm(252), 'a252'),
            new Ldai(new Imm(253)),
            new Sttoglobalrecord(new Imm(253), 'a253'),
            new Ldai(new Imm(254)),
            new Sttoglobalrecord(new Imm(254), 'a254'),
            new Ldai(new Imm(255)),
            new Sttoglobalrecord(new Imm(256), 'a255'),
            new Tryldglobalbyname(new Imm(257), 'call'),
            new Sta(v[3]),
            new Tryldglobalbyname(new Imm(258), 'a252'),
            new Sta(v[4]),
            new Tryldglobalbyname(new Imm(259), 'a253'),
            new Sta(v[5]),
            new Tryldglobalbyname(new Imm(260), 'a254'),
            new Sta(v[6]),
            new Tryldglobalbyname(new Imm(261), 'a255'),
            new Sta(v[7]),
            new Lda(v[3]),
            new Callrange(new Imm(255), new Imm(4), [v[4], v[5], v[6], v[7]]),
            new Returnundefined(),
        ];

        expect(checkInstructions(insns.slice(insns.length - 21), expected, checkRegisterNumber)).to.be.true;
    });

    it("VReg sequence of CalliDynRange is not continuous", function () {
        let pandaGen = new PandaGen('', creatAstFromSnippet(""), 0);
        let para1 = pandaGen.getTemp();
        let para2 = pandaGen.getTemp();
        let para3 = pandaGen.getTemp();
        let para4 = pandaGen.getTemp();
        let para5 = pandaGen.getTemp();
        let para6 = pandaGen.getTemp();

        pandaGen.call(ts.createNode(0), [para1, para2, para3, para4, para5, para6], false);

        pandaGen.freeTemps(para1, para3, para2);

        try {
            new RegAlloc().run(pandaGen);
        } catch (err) {
            expect(true).to.be.true;
            return;
        }
        expect(true).to.be.false;
    });

    it("VReg sequence of DynRange is not continuous", function () {
        let pandaGen = new PandaGen('', creatAstFromSnippet(""), 0);
        let para1 = pandaGen.getTemp();
        let para2 = pandaGen.getTemp();
        let para3 = pandaGen.getTemp();

        pandaGen.getInsns().push(new Callrange(new Imm(0), new Imm(3), [para1, para2, para3]))

        pandaGen.freeTemps(para1, para3, para2);

        try {
            new RegAlloc().run(pandaGen);
        } catch (err) {
            expect(true).to.be.true;
            return;
        }
        expect(true).to.be.false;
    });
});
