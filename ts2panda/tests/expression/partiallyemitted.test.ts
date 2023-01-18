import {
    expect
} from 'chai';
import 'mocha';
import {
    Returnundefined,
    Sttoglobalrecord,
    Tryldglobalbyname,
    Lda,
    VReg,
    Imm,
    IRNode,
    Sta,
    Mov,
    Stobjbyname,
    Dec
} from "../../src/irnodes";
import { checkInstructions, SnippetCompiler } from "../utils/base";
import { creatAstFromSnippet } from "../utils/asthelper"
import { PandaGen } from '../../src/pandagen';

describe("PartiallyEmittedExpressionTest", function () {
    it("createdPartiallyEmittedExprTest", function () {
        let snippetCompiler = new SnippetCompiler();
        snippetCompiler.compileAfter(`let a; let b; (a.name as string) = b`, 'test.ts');
        IRNode.pg = new PandaGen("", creatAstFromSnippet("let a; let b; (a.name as string) = b"), 0, undefined);
        let insns = snippetCompiler.getGlobalInsns();
        let expected = [
            new Lda(new VReg()),
            new Sttoglobalrecord(new Imm(0), 'a'),
            new Lda(new VReg()),
            new Sttoglobalrecord(new Imm(0), 'b'),
            new Tryldglobalbyname(new Imm(1), 'a'),
            new Sta(new VReg()),
            new Mov(new VReg(), new VReg()),
            new Tryldglobalbyname(new Imm(1), 'b'),
            new Stobjbyname(new Imm(2), "name", new VReg()),
            new Returnundefined()
        ];
        expect(checkInstructions(insns, expected)).to.be.true;
    });

    it("nestingParenthesizedPartiallyExprTest", function () {
        let snippetCompiler = new SnippetCompiler();
        snippetCompiler.compileAfter(
            `
                function reindexEdgeList(e: any, u: number):void {
                    --(((((e) as number)) as number) as number);
                }
            `, 'test.ts');
        IRNode.pg = new PandaGen("", creatAstFromSnippet(""), 0, undefined);
        let insns = snippetCompiler.getPandaGenByName("UnitTest.reindexEdgeList").getInsns();
        let expected = [
            new Lda(new VReg()),
            new Sta(new VReg()),
            new Lda(new VReg()),
            new Dec(new Imm(1)),
            new Sta(new VReg()),
            new Returnundefined()
        ];
        expect(checkInstructions(insns, expected)).to.be.true;
    });
});
