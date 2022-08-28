/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
import { checkInstructions, SnippetCompiler } from "./utils/base";
import {
    EcmaDefineclasswithbuffer,
    EcmaLdmodulevar,
    EcmaReturnundefined,
    EcmaStmodulevar,
    EcmaThrowundefinedifhole,
    Imm,
    LdaDyn,
    LdaStr,
    MovDyn,
    StaDyn,
    VReg
} from "../src/irnodes";
import { CmdOptions } from '../src/cmdOptions';


describe("ExportDeclaration", function () {

    it("exportClassTest ", function() {
        CmdOptions.isModules = () => {return true};
        let snippetCompiler = new SnippetCompiler();
        snippetCompiler.compile(`class C {}; export {C}`);
        CmdOptions.isModules = () => {return false};
        let funcMainInsns = snippetCompiler.getGlobalInsns();
        let classReg = new VReg();
        let expected = [
            new MovDyn(new VReg(), new VReg()),
            new EcmaDefineclasswithbuffer("#1#C", new Imm(0), new Imm(0), new VReg(), new VReg()),
            new StaDyn(classReg),
            new LdaDyn(classReg),
            new EcmaStmodulevar('C'),
            new EcmaReturnundefined(),
        ];
        expect(checkInstructions(funcMainInsns, expected)).to.be.true;
    });

    it("Re-exportImportVarTest ", function() {
        CmdOptions.isModules = () => {return true};
        let snippetCompiler = new SnippetCompiler();
        snippetCompiler.compile(`import a from 'test.js'; let v = a; export {a};`);
        CmdOptions.isModules = () => {return false};
        let funcMainInsns = snippetCompiler.getGlobalInsns();
        let a = new VReg();
        let v = new VReg();
        let name = new VReg();
        let expected = [
            new EcmaLdmodulevar("a", new Imm(0)),
            new StaDyn(a),
            new LdaStr("a"),
            new StaDyn(name),
            new EcmaThrowundefinedifhole(a, name),
            new LdaDyn(a),
            new StaDyn(v),
            new EcmaReturnundefined(),
        ];
        expect(checkInstructions(funcMainInsns, expected)).to.be.true;
    });
});