/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';


const COPYRIGHT_HEADER = "/* \n\
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd. \n\
 * Licensed under the Apache License, Version 2.0 (the \"License\"); \n\
 * you may not use this file except in compliance with the License. \n\
 * You may obtain a copy of the License at \n\
 * \n\
 * http://www.apache.org/licenses/LICENSE-2.0 \n\
 * \n\
 * Unless required by applicable law or agreed to in writing, software \n\
 * distributed under the License is distributed on an \"AS IS\" BASIS, \n\
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. \n\
 * See the License for the specific language governing permissions and \n\
 * limitations under the License. \n\
 */ \n\
";

// HTML tegs
const T_BR = "<br>";
const T_UNDERLINE = "<u>";
const T_END_UNDERLINE = "</u>";
const T_BOLD = "<b>";
const T_END_BOLD = "</b>";
const T_ITALIC = "<i>";
const T_END_ITALIC = "</i>";
const T_CODE = "<code>";
const T_END_CODE = "</code>";
const T_NBSP = "&nbsp;";
const T_HR = "<hr style=\\\"height:3px;\\\">";

// RST substititions
const CB_ = "|CB_";
const CB_R = "|CB_R|";
const CB_RULE = "|CB_RULE|";
const CB_BAD = "|CB_BAD|";
const CB_OK = "|CB_OK|";
const CB_SEE = "|CB_SEE|";

let MAKE_MD = false;    // flag to generate .md files

let doc_lines: string[];
let _line:number
let recNum: number;

let tegs: string[] = [];
let cooks: string[] = [];
let mdText: string[] = [];


const NEW_REC_HEADER = ".. _R";
const CODE_BLOCK = ".. code";  //  should be  ".. code-block" but in some places there is error in doc file

const CL = " \\";  // continue line


function syncReadFile(filename: string) {
  const contents = readFileSync(filename, 'utf-8');

  doc_lines = contents.split(/\r?\n/);

  // ✅ Read file line by line
  
  //doc_lines.forEach((line) => {

    //console.log(line);
  //});
  
  _line = 0;
  while(  _line < doc_lines.length ) {
	skipEmptyLines();  
  	if( doc_lines[_line].startsWith(NEW_REC_HEADER)) {
		makeRecept();
	} 
	else
		_line++;
  }

  return doc_lines;
}

// Data interface to Linter

enum NodeType {
    AnyType,
    SymbolType,
    UnionType,
    TupleType,
    ObjectLiteralNoContextType,
    ArrayLiteralNoContextType,
    ComputedPropertyName,
    LiteralAsPropertyName,
    TypeOfExpression,
    TupleLiteral,
    UnionLiteral,
    RegexLiteral,
    IsOperator,
    DestructuringParameter,
    YieldExpression,
    InterfaceOrEnumMerging,
    InterfaceExtendsClass,
    IndexMember,
    WithStatement,
    ThrowStatement,
    IndexedAccessType,
    UndefinedType,
    UnknownType,
    ForInStatement,
    InOperator,
    SpreadOperator,
    KeyOfOperator,
    ImportFromPath,
    FunctionExpression,

    TypeParameterWithDefaultValue,
    IntersectionType,
    ObjectTypeLiteral,
    LogicalWithNonBoolean,
    AddWithWrongType,
    BitOpWithWrongType,
    CommaOperator,
    TopLevelStmt,

    IfWithNonBoolean,
    DoWithNonBoolean,
    WhileWithNonBoolean,
    FuncWithoutReturnType,
    ArrowFunctionWithOmittedTypes,
    LambdaWithTypeParameters,
    ClassExpression,
    DestructuringAssignment,
    DestructuringDeclaration,

    ForOfNonArray,
    VarDeclaration,
    CatchWithUnsupportedType,

    DeleteOperator,
    DeclWithDuplicateName,
    FuncOptionalParams,

    UnaryArithmNotNumber,
    LogNotWithNotBool,
    ConstructorType,
    CallSignature,
    TemplateLiteral,
    TypeAssertion,
    FunctionOverload,
    ConstructorOverload,

    PrivateIdentifier,
    LocalFunction,
    SwitchSelectorInvalidType,
    CaseExpressionNonConst,
    ConditionalType,
    MappedType,
    NamespaceAsObject,
    NonDeclarationInNamespace,
    GeneratorFunction,
    FunctionContainsThis,
    PropertyAccessByIndex,
    JsxElement,
    EnumMemberWithInitializer,

    ImplementsClass,
    MultipleStaticBlocks,
    //Decorators, // It's not a problem and counted temporary just to have statistic of decorators use.
    ThisType,
    InferType,
    SpreadAssignment,
    IntefaceExtendDifProps,
    DynamicTypeCheck,

    TypeOnlyImport,
    TypeOnlyExport,
    DefaultImport,
    DefaultExport,
    ExportRenaming,
    ExportListDeclaration,
    ReExporting,
    ExportAssignment,
    ImportAssignment,

    ObjectRuntimeCheck,
    GenericCallNoTypeArgs,

    BigIntType,
    BigIntLiteral,
    StringLiteralType,
    InterfaceOptionalProp,
    ParameterProperties,
    InstanceofUnsupported,
    GenericArrayType,

    LAST_NODE_TYPE // this should always be last enum`
}




//
// utility functions
//
function translateLine( s: string ) : string {
	let line = s;
	line = line.replace( CB_BAD,  "TypeScript");
	line = line.replace( CB_OK,  "ArkTS");
	//line = line.replace( "|CB_R|", "Recipe");
	//.. |CB_RULE| replace:: Rule
	//.. |CB_SEE| replace:: See also
	line = line.replace( "|JS|", "JavaScript");
	line = line.replace( "|LANG|", "ArkTS"); //.. |LANG| replace:: {lang}
	line = line.replace( "|TS|",  "TypeScript");

	return line;
}


function translateTeg( s: string) :string {
	let ss = s.split("\`\`");
	let teg = "";
	ss.forEach((line) => { teg += "\'" + line; } );
        return teg.replace("\'"," ").trim();
	//return teg.replaceAll("\`\`", "\'");
}


function makeHdr( s: string) :string {
        let ss = s.split("\`\`");
        let teg: string ="";
        ss.forEach((line) => { teg += "\'" + line; } );
        return teg.replace("\'","");
}


function highlightCode( s: string ): string {
	let ss = s.split("\`\`");
	let line = ss[0];
	for( let i = 1; i < ss.length; i++ ) {
		if( (i % 2) === 0 )
			line += T_END_CODE;
		else
			line += T_CODE;
		line += ss[i];
	}
	return line;
}

function escapeSym( s: string ): string {
	let ss = s.split("\"");
	let esc_line = "";
	ss.forEach( (line) => { esc_line += "\\\"" + line; });
	return esc_line.replace("\\\"", "");
}

function setNBSP( s: string ): string {
	let ss = "";
	let flag = true;
	for( let ch of s ) {
		if( ch !== " " && ch !== "\t" )
			flag = false;
		if( flag && ch === " " )
			ss += T_NBSP;
		else if( flag && ch ==="\t" )
			ss += T_NBSP + T_NBSP +  T_NBSP + T_NBSP +  T_NBSP + T_NBSP +  T_NBSP + T_NBSP ;
		else
			ss  += ch;
	}
	return ss;
}

function skipEmptyLines() {
	while( _line < doc_lines.length ) {
		let s = doc_lines[_line];
		s = s.trim();
		if( s !== "")
			break;
		_line++;
	}
}

function isHeader(): boolean {
	return  doc_lines[ _line ].startsWith( CB_ ) || doc_lines[ _line ].startsWith( ".." ) ;  
}



//
// parsing functions
//
function makeRecept() {
	recNum = Number(doc_lines[_line].slice(NEW_REC_HEADER.length, NEW_REC_HEADER.length+3))
	console.log("cookBookMsg[ " + recNum + " ] = \"" + CL);
	_line++;
	mdText = [];
	makeTeg();
	makeBody();
	makeBad();
	makeOk();
	makeSee();

	// emit .md file
	let mdFileName = join("./md", "recepie" + recNum + ".md" );
	writeFileSync( mdFileName, "", { flag: 'w', });
	mdText.forEach((mdLine) => {
	console.error(mdLine);
        writeFileSync(mdFileName, mdLine + '\n', { flag: "a+"} )
    });

	console.log("\";");
	console.log("");
}


function makeTeg() {
	console.error(">>>TEG: " + doc_lines[_line]);
	//while( !doc_lines[_line].startsWith( CB_R ) ) 
	while ( _line < doc_lines.length && !isHeader() )
		_line++;
	
console.error(">>>TEG>>>: " + _line + " -> " + doc_lines[_line]);
	if( ! doc_lines[ _line ].startsWith( CB_R ) )
		return;
	let line = doc_lines[ _line ].split( CB_R )[1];

	mdText.push("# Recipe No. " + recNum + ": " + line.split(':')[1] );
	mdText.push("");

	line = escapeSym( translateLine(line) );
	let teg = translateTeg( line );
	//console.log( teg );
	//let hdr = makeHdr( line );
	let hdr = highlightCode(line);
	console.log(hdr + T_BR + CL);
	tegs[ recNum ] = teg;
	_line++;
}


function makeBody(): string {
	let body = "";

	//while( !doc_lines[ _line ].startsWith( CB_RULE ) ){
	while( _line < doc_lines.length && !isHeader()) {
		console.error("in rule SKIP: " + doc_lines[ _line ]);
		_line++;
	}
	if( !doc_lines[ _line ].startsWith( CB_RULE ) )
		return "";

	_line++; _line++; // skip underline
	console.log( T_HR + T_BOLD + "Rule" + T_END_BOLD + T_BR + CL );

	mdText.push("## Rule");
	mdText.push("");

	while( !isHeader() /*!doc_lines[_line].startsWith("|CB_") && !doc_lines[_line].startsWith("..") */ ) {
		//skipEmptyLines();
		let s = translateLine( doc_lines[_line] );

		mdText.push(s);

		s = highlightCode( s );
		s = escapeSym( s );
		console.log(s + CL);
	
		body += s;
		_line++;
	}
	console.log(T_BR + CL);

	mdText.push("");

	return body;
}



function makeBad(): string {
	let badCode ="";
	
	while( !isHeader ) {
                console.error("in TS SKIP: " + doc_lines[_line]);
                _line++;
        }
	if( ! doc_lines[_line].startsWith( CB_BAD ) ) {
		return "";
	}

    _line++; _line++; // skip underline
	console.log( T_HR + T_BOLD + "TypeScript" + T_END_BOLD + T_BR + CL );

	mdText.push("## TypeScript");
	mdText.push("");

    while( _line < doc_lines.length && !isHeader() /* !doc_lines[_line].startsWith( CB_ ) &&  !doc_lines[_line].startsWith("..") */ ) {
                //skipEmptyLines();
                let s = translateLine( doc_lines[_line] );

                mdText.push( s );

                s = highlightCode( s );
                console.log(s + CL);

                badCode += s;
                _line++;
    }

	skipEmptyLines();
	if( doc_lines[_line++].startsWith( CODE_BLOCK ) ) {
		console.log( T_CODE + CL );
		while( _line < doc_lines.length && !isHeader() /* !doc_lines[_line].startsWith( CB_ ) && !doc_lines[_line].startsWith("..") */ ) {

			mdText.push( doc_lines[_line] );

			console.log( setNBSP( escapeSym(doc_lines[_line]) ) + T_BR + CL );
			_line++;
		}
		console.log( T_END_CODE + T_BR + CL );
	}

    mdText.push("");

	return badCode;
}


function makeOk(): string {
	let goodCode = "";

	while( !isHeader() ) {
                console.error( "in Ark SKIP: " + doc_lines[ _line ] );
                _line++;
        }
	if( !doc_lines[_line].startsWith(CB_OK) ) {
		return "";
	}

    _line++; _line++; // skip underline
    console.log( T_HR + T_BOLD + "ArkTS" + T_END_BOLD + T_BR + CL );

    mdText.push("## ArkTS");
    mdText.push("");
        
	while(  _line < doc_lines.length && !isHeader() /* !doc_lines[ _line ].startsWith( CB_ ) &&  !doc_lines[ _line ].startsWith( ".." ) */ ) {
                //skipEmptyLines();
                let s = translateLine( doc_lines[ _line ] );

                mdText.push( s );

                s = highlightCode( s );
                console.log(s + CL);

                goodCode += s;
                _line++;
        }

	skipEmptyLines();
    if( doc_lines[ _line++ ].startsWith( CODE_BLOCK ) ) {
        console.log( T_CODE + CL );
                while(  _line < doc_lines.length && !isHeader() /* !doc_lines[ _line ].startsWith( CB_ ) &&  !doc_lines[ _line ].startsWith("..")*/ ) {

                        mdText.push( doc_lines[_line] );

                        console.log( setNBSP( escapeSym(doc_lines[ _line ]) ) + T_BR + CL );
                        _line++;
                }
                console.log( T_END_CODE + T_BR + CL);
    }

    mdText.push("");

	return goodCode;
}


function makeSee( ): string {

    mdText.push("## See also");
    mdText.push("");

	console.error("#" + recNum + " PASSED: " + doc_lines[_line]);
	while( _line < doc_lines.length && !doc_lines[ _line ].startsWith( ".." ) ) {

        mdText.push( doc_lines[_line] );

		_line++;
	}

    mdText.push("");

	return "";
}


//
// Main routie
//
let commandLineArgs = process.argv.slice(2);
if (commandLineArgs.length === 0) {
	console.log("Command line error: no arguments");
	process.exit(-1);
}
if( commandLineArgs[0] == '-md') {
    commandLineArgs = process.argv.slice(3);
    MAKE_MD = true;
}
let inFileName = commandLineArgs[0];
//console.log(inFileName);
console.log(COPYRIGHT_HEADER);
console.log("export var cookBookMsg: string[] = []; \n");
console.log("export var cookBookTag: string[] = []; \n");
syncReadFile( inFileName);

for( recNum = 1; recNum < tegs.length; recNum++ ) {
	console.log( "cookBookTag[ " + recNum + " ] = \"" + ( tegs[ recNum ] ?  tegs[ recNum ] : "" ) + "\";" );
}

