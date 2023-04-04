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
    Dynamicimport,
    Callarg0,
    Callarg1,
    Callargs2,
    Callargs3,
    Callrange,
    WideCallrange,
    Callthis0,
    Callthis1,
    Callthis2,
    Callthis3,
    Callthisrange,
    WideCallthisrange,
    Closeiterator,
    Copydataproperties,
    Createarraywithbuffer,
    Createemptyarray,
    Createemptyobject,
    Createobjectwithbuffer,
    Createobjectwithexcludedkeys,
    Createregexpwithliteral,
    Debugger,
    Defineclasswithbuffer,
    Definefunc,
    Definegettersetterbyvalue,
    Definemethod,
    Delobjprop,
    Getiterator,
    Getnextpropname,
    Getpropiterator,
    Getmodulenamespace,
    Isfalse,
    Istrue,
    Ldglobalvar,
    Ldlexvar,
    Ldobjbyindex,
    Ldobjbyname,
    Ldobjbyvalue,
    Ldsuperbyname,
    Ldsuperbyvalue,
    Newlexenv,
    Newlexenvwithname,
    Newobjrange,
    Poplexenv,
    Returnundefined,
    Setobjectwithproto,
    Starrayspread,
    Stconsttoglobalrecord,
    Stglobalvar,
    Stlexvar,
    Stmodulevar,
    Stobjbyindex,
    Stobjbyname,
    Stobjbyvalue,
    Stownbyindex,
    Stownbyname,
    Stownbynamewithnameset,
    Stownbyvalue,
    Stownbyvaluewithnameset,
    Stsuperbyname,
    Stsuperbyvalue,
    Supercallthisrange,
    Supercallspread,
    ThrowConstassignment,
    ThrowDeletesuperproperty,
    Throw,
    ThrowIfnotobject,
    ThrowIfsupernotcorrectcall,
    ThrowPatternnoncoercible,
    ThrowNotexists,
    ThrowUndefinedifholewithname,
    Tryldglobalbyname,
    Trystglobalbyname,
    Fldai,
    Imm,
    IRNode,
    Jmp,
    Label,
    Lda,
    Ldai,
    LdaStr,
    Mov,
    Sta,
    Ldbigint,
    VReg,
    WideNewlexenv,
    WideNewlexenvwithname,
    WideLdlexvar,
    WideStlexvar,
    WideLdobjbyindex,
    WideStobjbyindex,
    WideStownbyindex,
    WideNewobjrange,
    WideCreateobjectwithexcludedkeys,
    WideSupercallthisrange,
    WideSupercallarrowrange,
    Supercallarrowrange,
    WideGetmodulenamespace,
    Ldlocalmodulevar,
    WideLdlocalmodulevar,
    Ldexternalmodulevar,
    WideLdexternalmodulevar,
    WideStmodulevar,
    Sttoglobalrecord
} from "../irnodes";
import { MAX_INT16, MAX_INT8 } from "./util";

export function loadAccumulatorInt(value: number): IRNode {
    return new Ldai(new Imm(value));
}

export function loadAccumulatorFloat(value: number): IRNode {
    return new Fldai(new Imm(value));
}

export function loadAccumulatorString(value: string): IRNode {
    return new LdaStr(value);
}

export function loadAccumulator(vreg: VReg): IRNode {
    return new Lda(vreg);
}

export function storeAccumulator(vreg: VReg): IRNode {
    return new Sta(vreg);
}

export function deleteObjProperty(obj: VReg): IRNode {
    return new Delobjprop(obj);
}

export function moveVreg(vd: VReg, vs: VReg): IRNode {
    return new Mov(vd, vs);
}

export function jumpTarget(target: Label): IRNode {
    return new Jmp(target);
}

export function creatDebugger(): IRNode {
    return new Debugger();
}

export function throwException(): IRNode {
    return new Throw();
}

export function throwConstAssignment(name: VReg): IRNode {
    return new ThrowConstassignment(name);
}

export function throwUndefinedIfHole(name: string): IRNode {
    return new ThrowUndefinedifholewithname(name);
}

export function throwThrowNotExists(): IRNode {
    return new ThrowNotexists();
}

export function throwDeleteSuperProperty(): IRNode {
    return new ThrowDeletesuperproperty();
}

export function newLexicalEnv(numVars: number, scopeInfoId: string | undefined): IRNode {
    if (scopeInfoId === undefined) {
        return numVars <= MAX_INT8 ? new Newlexenv(new Imm(numVars)) :
                                     new WideNewlexenv(new Imm(numVars));
    }
    return numVars <= MAX_INT8 ? new Newlexenvwithname(new Imm(numVars), scopeInfoId) :
                                 new WideNewlexenvwithname(new Imm(numVars), scopeInfoId);
}

export function popLexicalEnv(): IRNode {
    return new Poplexenv();
}

export function loadLexicalVar(level: number, slot: number): IRNode {
    if ((level > MAX_INT8) || (slot > MAX_INT8)) {
        return new WideLdlexvar(new Imm(level), new Imm(slot));
    }
    return new Ldlexvar(new Imm(level), new Imm(slot));
}

export function storeLexicalVar(level: number, slot: number): IRNode {
    if ((level > MAX_INT8) || (slot > MAX_INT8)) {
        return new WideStlexvar(new Imm(level), new Imm(slot));
    }
    return new Stlexvar(new Imm(level), new Imm(slot));
}

export function tryLoadGlobalByName(key: string): IRNode {
    return new Tryldglobalbyname(new Imm(0), key);
}

export function tryStoreGlobalByName(key: string): IRNode {
    return new Trystglobalbyname(new Imm(0), key);
}

export function loadGlobalVar(name: string): IRNode {
    return new Ldglobalvar(new Imm(0), name);
}

export function storeGlobalVar(name: string): IRNode {
    return new Stglobalvar(new Imm(0), name);
}

export function loadObjByName(key: string): IRNode {
    return new Ldobjbyname(new Imm(0), key);
}

export function storeObjByName(obj: VReg, key: string): IRNode {
    return new Stobjbyname(new Imm(0), key, obj);
}

export function loadObjByIndex(index: number): IRNode {
    return index <= MAX_INT16 ? new Ldobjbyindex(new Imm(0), new Imm(index)) :
                                new WideLdobjbyindex(new Imm(index));
}

export function storeObjByIndex(obj: VReg, index: number): IRNode {
    return index <= MAX_INT16 ? new Stobjbyindex(new Imm(0), obj, new Imm(index)) :
                                new WideStobjbyindex(obj, new Imm(index));
}

export function loadObjByValue(obj: VReg): IRNode {
    return new Ldobjbyvalue(new Imm(0), obj);
}

export function storeObjByValue(obj: VReg, prop: VReg): IRNode {
    return new Stobjbyvalue(new Imm(0), obj, prop);
}

export function storeOwnByName(obj: VReg, key: string, nameSetting: boolean): IRNode {
    return nameSetting ? new Stownbynamewithnameset(new Imm(0), key, obj) :
                         new Stownbyname(new Imm(0), key, obj);
}

export function storeOwnByIndex(obj: VReg, index: number): IRNode {
    return index <= MAX_INT16 ? new Stownbyindex(new Imm(0), obj, new Imm(index)) :
                                new WideStownbyindex(obj, new Imm(index));
}

export function storeOwnByValue(obj: VReg, value: VReg, nameSetting: boolean): IRNode {
    return nameSetting ? new Stownbyvaluewithnameset(new Imm(0), obj, value) :
                         new Stownbyvalue(new Imm(0), obj, value);
}

export function throwIfSuperNotCorrectCall(num: number): IRNode {
    return new ThrowIfsupernotcorrectcall(new Imm(num));
}

export function call(args: VReg[], passThis: boolean): IRNode {
    let length = args.length;
    let insn: IRNode;
    if (!passThis) {
        switch (length) {
            case 0:
                insn = new Callarg0(new Imm(0));
                break;
            case 1:
                insn = new Callarg1(new Imm(0), args[0]);
                break;
            case 2:
                insn = new Callargs2(new Imm(0), args[0], args[1]);
                break;
            case 3:
                insn = new Callargs3(new Imm(0), args[0], args[1], args[2]);
                break;
            default:
                insn = length <= MAX_INT8 ? new Callrange(new Imm(0), new Imm(length), args) :
                                                  new WideCallrange(new Imm(length), args);
        }
    } else {
        insn = callThis(args);
    }

    return insn;
}

function callThis(args: Array<VReg>): IRNode {
    let insn: IRNode;
    let thisReg: VReg = args[0];
    let length = args.length;
    switch (length) {
        case 1: {
            insn = new Callthis0(new Imm(0), thisReg);
            break;
        }
        case 2: {
            insn = new Callthis1(new Imm(0), thisReg, args[1]);
            break;
        }
        case 3: {
            insn = new Callthis2(new Imm(0), thisReg, args[1], args[2]);
            break;
        }
        case 4: {
            insn = new Callthis3(new Imm(0), thisReg, args[1], args[2], args[3]);
            break;
        }
        default: {
            insn = (length - 1) <= MAX_INT8 ? new Callthisrange(new Imm(0), new Imm(length - 1), args) :
                                              new WideCallthisrange(new Imm(length - 1), args);
            break;
        }
    }
    return insn;
}

export function newObject(args: VReg[]): IRNode {
    let length = args.length;
    return length <= MAX_INT8 ? new Newobjrange(new Imm(0), new Imm(length), args) :
                                new WideNewobjrange(new Imm(length), args);
}

export function getPropIterator(): IRNode {
    return new Getpropiterator();
}

export function getNextPropName(iter: VReg): IRNode {
    return new Getnextpropname(iter);
}

export function returnUndefined(): IRNode {
    return new Returnundefined();
}

export function createEmptyObject(): IRNode {
    return new Createemptyobject();
}

export function createObjectWithBuffer(bufferId: string): IRNode {
    return new Createobjectwithbuffer(new Imm(0), bufferId);
}

export function setObjectWithProto(proto: VReg): IRNode {
    return new Setobjectwithproto(new Imm(0), proto);
}

export function copyDataProperties(dstObj: VReg): IRNode {
    return new Copydataproperties(dstObj);
}

export function defineGetterSetterByValue(obj: VReg, name: VReg, getter: VReg, setter: VReg): IRNode {
    return new Definegettersetterbyvalue(obj, name, getter, setter);
}

export function createEmptyArray(): IRNode {
    return new Createemptyarray(new Imm(0));
}

export function createArrayWithBuffer(bufferId: string): IRNode {
    return new Createarraywithbuffer(new Imm(0), bufferId);
}

export function storeArraySpread(array: VReg, index: VReg): IRNode {
    return new Starrayspread(array, index);
}

export function defineClassWithBuffer(id: string, litId: string, parameterLength: number, base: VReg): IRNode {
    return new Defineclasswithbuffer(new Imm(0), id, litId, new Imm(parameterLength), base);
}

export function createObjectWithExcludedKeys(obj: VReg, args: VReg[]): IRNode {
    let followedArgs = args.length - 1;
    return followedArgs <= MAX_INT8 ? new Createobjectwithexcludedkeys(new Imm(followedArgs), obj, args) :
                                      new WideCreateobjectwithexcludedkeys(new Imm(followedArgs), obj, args);
}

export function throwObjectNonCoercible(): IRNode {
    return new ThrowPatternnoncoercible();
}

export function throwIfNotObject(v: VReg): IRNode {
    return new ThrowIfnotobject(v);
}

export function getIterator(): IRNode {
    return new Getiterator(new Imm(0));
}

export function closeIterator(iter: VReg): IRNode {
    return new Closeiterator(new Imm(0), iter);
}

export function superCall(num: number, args: Array<VReg>): IRNode {
    return num <= MAX_INT8 ? new Supercallthisrange(new Imm(0), new Imm(num), args) :
                             new WideSupercallthisrange(new Imm(num), args);
}

export function superCallInArrow(num: number, args: Array<VReg>): IRNode {
    return num <= MAX_INT8 ? new Supercallarrowrange(new Imm(0), new Imm(num), args) :
                             new WideSupercallarrowrange(new Imm(num), args);
}

export function superCallSpread(vs: VReg): IRNode {
    return new Supercallspread(new Imm(0), vs);
}

export function ldSuperByName(key: string): IRNode {
    return new Ldsuperbyname(new Imm(0), key); // obj is in acc
}

export function stSuperByName(obj: VReg, key: string): IRNode {
    return new Stsuperbyname(new Imm(0), key, obj);
}

export function stSuperByValue(obj: VReg, prop: VReg): IRNode {
    return new Stsuperbyvalue(new Imm(0), obj, prop);
}

export function ldSuperByValue(obj: VReg): IRNode {
    return new Ldsuperbyvalue(new Imm(0), obj); // prop is in acc
}

export function loadLocalModuleVariable(index: number): IRNode {
    return index <= MAX_INT8 ? new Ldlocalmodulevar(new Imm(index)) : new WideLdlocalmodulevar(new Imm(index));
}

export function loadExternalModuleVariable(index: number): IRNode {
    return index <= MAX_INT8 ? new Ldexternalmodulevar(new Imm(index)) : new WideLdexternalmodulevar(new Imm(index));
}


export function dynamicImport() {
    return new Dynamicimport();
}

export function storeModuleVariable(index: number): IRNode {
    return index <= MAX_INT8 ? new Stmodulevar(new Imm(index)) : new WideStmodulevar(new Imm(index));
}

export function getModuleNamespace(moduleRequestIdx: number): IRNode {
    return moduleRequestIdx <= MAX_INT8 ? new Getmodulenamespace(new Imm(moduleRequestIdx)) :
                                          new WideGetmodulenamespace(new Imm(moduleRequestIdx));
}

export function defineFunc(name: string, paramLength: number): IRNode {
    return new Definefunc(new Imm(0), name, new Imm(paramLength));
}

export function defineMethod(name: string, paramLength: number): IRNode {
    return new Definemethod(new Imm(0), name, new Imm(paramLength));
}

export function isTrue(): IRNode {
    return new Istrue();
}

export function isFalse(): IRNode {
    return new Isfalse();
}

export function createRegExpWithLiteral(pattern: string, flags: number): IRNode {
    return new Createregexpwithliteral(new Imm(0), pattern, new Imm(flags));
}

export function stLetOrClassToGlobalRecord(name: string): IRNode {
    return new Sttoglobalrecord(new Imm(0), name);
}

export function stConstToGlobalRecord(name: string): IRNode {
    return new Stconsttoglobalrecord(new Imm(0), name);
}

export function loadAccumulatorBigInt(value: string): IRNode {
    return new Ldbigint(value);
}