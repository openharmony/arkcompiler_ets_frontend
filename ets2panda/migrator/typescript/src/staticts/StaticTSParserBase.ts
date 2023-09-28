/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

import { Parser, TokenStream, Vocabulary } from "antlr4ts" 

/**
 * All parser methods that used in grammar (p, prev, notLineTerminator, etc.)
 * should start with lower case char similar to parser rules.
 */
export class StaticTSParserBase extends Parser {

    // These are context-dependent keywords, i.e. those that
    // can't be used as identifiers only in specific contexts
    public static CATCH = "catch"; // keyword in try statement context
    public static DEFAULT = "default"; // keyword in switch statement context
    public static EXTENDS = "extends"; // keyword in class/interface declaration context
    public static FROM = "from"; // keyword in import declaration context
    public static GET = "get"; // keyword in accessor declaration context
    public static IMPLEMENTS = "implements"; // keyword in class declaration context
    public static IN = "in"; // keyword in type argument and type parameter contexts
    public static OF = "of"; // keyword in for statement context
    public static OUT = "out"; // keyword in type argument and type parameter contexts
    public static READONLY = "readonly"; // keyword in field declaration context
    public static SET = "set"; // keyword in accessor declaration context
    public static THROWS = "throws"; // keyword in function/method declaration context
    public static RETHROWS = "rethrows"; // keyword in function/method declaration context

    // The following keywords are reserved for use as predefined type names
    // and cannot appear as user-defined type names; otherwise, they can be
    // used freely as identifiers.
    public static BOOLEAN = "boolean";
    public static BYTE = "byte";
    public static CHAR = "char";
    public static DOUBLE = "double";
    public static FLOAT = "float";
    public static INT = "int";
    public static LONG = "long";
    public static SHORT = "short";
    public static UBYTE = "ubyte";
    public static UINT = "uint";
    public static ULONG = "ulong";
    public static USHORT = "ushort";
    public static VOID = "void";

    // The following are the names of built-in types.
    // They are not reserved in any way.
    public static STRING = "String";
    public static OBJECT = "Object";
    public static NEVER = "Never";

    constructor(input: TokenStream) {
        super(input);
    }

    get ruleNames(): string[] {
        return null;
    }
    get grammarFileName(): string {
        return "";
    }
    get vocabulary(): Vocabulary {
        return null;
    }
    protected p(str: string): boolean {
        return false;
    }
    protected prev(str: string): boolean {
        return false;
    }
    protected n(str: string): boolean {
        return false;
    }
    protected next(str: string): boolean {
        return false;
    }
    protected predefinedTypeAhead(): boolean {
        return false;
    }
    protected notLineTerminator(): boolean {
        return false;
    }
    protected notOpenBraceAndNotFunction(): boolean {
        return false;
    }
    protected closeBrace(): boolean {
        return false;
    }
    protected lineTerminatorAhead(): boolean {
        return false;
    }
}
