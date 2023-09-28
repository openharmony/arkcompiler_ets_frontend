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

const CODE_PROLOGUE = "export const cookBookMsg: string[] = [];\n\
export const cookBookTag: string[] = [];\n\
\n\
for( let i = 0; i <= 150; i++) {\n\
  cookBookMsg[ i ] = '';\n\
}\n\
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
const T_HR = '<hr style="height:3px;">';

// RST substititions
const CB_ = "|CB_";
const CB_R = "|CB_R|";
const CB_RULE = "|CB_RULE|";
const CB_BAD = "|CB_BAD|";
const CB_OK = "|CB_OK|";
const CB_ERROR = "|CB_ERROR|"; //replace:: **Severity: error**
const CB_WARNING = "|CB_WARNING|"; //replace:: **Severity: warning**
const CB_SEE = "|CB_SEE|";
const CB_REF = ":ref:";
const CB_META = ".. meta";
const CB_FIX = ":fix:";

const NEW_REC_HEADER = /.. _R\d\d\d:/;
const CODE_BLOCK = ".. code";  //  should be  ".. code-block" but in some places there is error in doc file

let MAKE_MD = false;    // flag to generate .md files

let doc_lines: string[];
let _line:number
let recNum: number;

let tegs: string[] = [];
let ruleNames: string[] = [];
let cooks: string[] = [];
let mdText: string[] = [];
let fixTitles: Map<number, string> = new Map();


const CL = " \\";  // continue line
const STR_DLMTR = "\'";


function syncReadFile(filename: string) {
  const contents = readFileSync(filename, 'utf-8');

  doc_lines = contents.split(/\r?\n/);

// make table of rule names
  _line = 0;
  let ruleNum = -1;
  while(  _line < doc_lines.length ) {
	const line = doc_lines[ _line ]
	if(NEW_REC_HEADER.test(line)) {
		ruleNum = Number(line.replace(/\D/g, ''))
console.log(">>>>>>> START RULE " + ruleNum + ":")		
console.log("                    NUMBER: " + ruleNum)		
	}
    if( doc_lines[ _line ].startsWith( CB_R ) ) {
      let line = doc_lines[ _line ].split( CB_R )[1];
      //let tegNumStr = line.split(':')[0];
      //let ruleNum = Number(tegNumStr.split('#')[1]);
      ruleNames[ ruleNum ] = line; //line.split(':')[1];
      _line++;
      needHeader();
      if( doc_lines[ _line ].startsWith( CB_RULE ) ) {
        line = doc_lines[ _line ].trim().replace( CB_RULE, "").trim();
        ruleNames[ ruleNum ] = ruleNames[ ruleNum ] + " (" +  line  + ")";
      }
    }
    _line ++;
  }

  // scan text
  _line = 0;
  while(  _line < doc_lines.length ) {
	skipEmptyLines();  
	const line = doc_lines[_line]
  	if(NEW_REC_HEADER.test(line)) {
		makeRecept();
	} 
	else
		_line++;
  }

  return doc_lines;
}


//
// utility functions
//

function replaceAll( s: string, from: string, to: string): string {
    let ss = s.split(from);
    let outStr = "";
    ss.forEach( (line) => { outStr += to + line; });

    return outStr.replace( to, "");   // remove 1st 'to' substring
}

function translateLine( s: string ) : string {
	let line = s;
	line = line.replace( CB_BAD,  "TypeScript");
	line = line.replace( CB_OK,  "ArkTS");
	//line = line.replace( "|CB_R|", "Recipe");
	//.. |CB_RULE| replace:: Rule
	line = line.replace( CB_ERROR, "**Severity: error**" );
	line = line.replace( CB_WARNING, "**Severity: warning**" );
	line = line.replace(CB_SEE, "## See also" );

	line = replaceAll(line, "|JS|", "JavaScript");
	line = replaceAll(line, "|LANG|", "ArkTS"); //.. |LANG| replace:: {lang}
	line = replaceAll(line, "|TS|",  "TypeScript");

	return line;
}


function translateTeg( s: string) :string {
	return  replaceAll( s, "\`\`", '"' ).trim();
}


function makeHdr( s: string) :string {
        return replaceAll( s, "\`\`", "\'" );
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
    let ss = replaceAll(s, "\'", "\\\'");
    return replaceAll(ss, "\"", "\\\"");
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

function needHeader() {
    while ( _line < doc_lines.length && !isHeader() )
		_line++;
}

function isFixTitle(): boolean {
    return doc_lines[_line].trimStart().startsWith(CB_FIX)
}

//
// parsing functions
//

function makeFixTitle() {
    while (_line < doc_lines.length && !isHeader() && !isFixTitle()) {
        _line++;
    }

    if (isFixTitle()) {
        const title = doc_lines[_line].split(CB_FIX)[1].trim();
        fixTitles.set(recNum, escapeSym(title));
    }
}

function makeRecept() {
	const line = doc_lines[_line]
	recNum = Number(line.replace(/\D/g, ''))
	console.log("cookBookMsg[ " + recNum + " ] = " + STR_DLMTR + CL);
	_line++;
	mdText = [];
	makeTeg();
	makeBody();
	makeBad();
	makeOk();
	makeSee();

	// emit .md file
	let mdFileName = join("./md", "recipe" + recNum + ".md" );
	writeFileSync( mdFileName, "", { flag: 'w', });
	mdText.forEach((mdLine) => {
console.error("MD> " + mdLine);
        writeFileSync(mdFileName, mdLine + '\n', { flag: "a+"} )
    });

	console.log(STR_DLMTR + ";");
	console.log("");
}


function makeTeg() {
	needHeader();
console.error(">>>TEG>>>: " + _line + " -> " + doc_lines[_line]);
	if( ! doc_lines[ _line ].startsWith( CB_R ) )
		return;
	let line = doc_lines[ _line ].split( CB_R )[1];

	mdText.push("# " + translateLine( line )); //.split(':')[1] );
	mdText.push("");

	line = escapeSym( translateLine(line) );
	let teg = translateTeg( line );
	let hdr = highlightCode(line);
	console.log(hdr + T_BR + CL);
	tegs[ recNum ] = teg; //.split(':')[1];
	_line++;
}


function makeBody(): string {
	let body = "";

	needHeader();
console.error(">>>BODY HDR>>>: " + + _line + " -> " + doc_lines[_line]);
	if( !doc_lines[ _line ].startsWith( CB_RULE ) )
		return "";

    let line = doc_lines[ _line ].trim();
    let md_line = line;
    line = line.replace( CB_RULE, "");
    line = escapeSym( translateLine(line) );
    tegs[ recNum ] = tegs[ recNum ].trim() + " (" + replaceAll(translateTeg(line), '"', '') + ")";

	_line++; _line++; // skip underline
	console.log( T_HR + T_BOLD + "Rule" + T_END_BOLD + T_BR + CL );

	mdText.push( md_line.replace( CB_RULE, "Rule" ) ); //("## Rule");
	mdText.push("");

    needHeader();
console.error(">>>BODY 2 HDR>>>: " + + _line + " -> " + doc_lines[_line]);
    if( doc_lines[ _line ].startsWith(CB_META) ) {
        _line++;
        makeFixTitle();
        needHeader();
console.error(">>>BODY 3 HDR>>>: " + + _line + " -> " + doc_lines[_line]);
    }
    //_line++;
	while( !isHeader() || doc_lines[ _line ].startsWith( CB_ERROR ) || doc_lines[ _line ].startsWith( CB_WARNING ) ) {
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
	
	needHeader();
console.error(">>>makeBAD HDR>>>: " + doc_lines[_line]);
	if( ! doc_lines[_line].startsWith( CB_BAD ) ) {
		return "";
	}
    _line++; _line++; // skip underline

	console.log( T_HR + T_BOLD + "TypeScript" + T_END_BOLD + T_BR + CL );

	mdText.push("## TypeScript");
	mdText.push("");

    while( _line < doc_lines.length && !isHeader() ) {
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
	    mdText.push("```");
		console.log( T_CODE + CL );
		while( _line < doc_lines.length && !isHeader() ) {
			mdText.push( doc_lines[_line] );
			console.log( setNBSP( escapeSym(doc_lines[_line]) ) + T_BR + CL );
			_line++;
		}
		console.log( T_END_CODE + T_BR + CL );

		mdText.push("```");
	}
    mdText.push("");

	return badCode;
}


function makeOk(): string {
	let goodCode = "";

    needHeader();
console.error( ">>>makeOK HDR>>>: " + doc_lines[ _line ] );
	if( _line >= doc_lines.length || !doc_lines[_line].startsWith(CB_OK) ) {
		return "";
	}
    _line++; _line++; // skip underline
    console.log( T_HR + T_BOLD + "ArkTS" + T_END_BOLD + T_BR + CL );

    mdText.push("## ArkTS");
    mdText.push("");
        
	while(  _line < doc_lines.length && !isHeader() ) {
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

        mdText.push("```");

        while(  _line < doc_lines.length && !isHeader() ) {
            mdText.push( doc_lines[_line] );
            console.log( setNBSP( escapeSym(doc_lines[ _line ]) ) + T_BR + CL );
            _line++;
        }
        console.log( T_END_CODE + T_BR + CL);

        mdText.push("```");
    }

    mdText.push("");

	return goodCode;
}


function makeSee( ): string {
    //mdText.push("## See also");
    //mdText.push("");
    const RECIPE = "Recipe ";
console.error(">>> #" + recNum + " PASSED: " + doc_lines[_line]);
	while( _line < doc_lines.length && !doc_lines[ _line ].startsWith( ".." ) ) {

        let s = translateLine( doc_lines[_line] );

        if( s.split(CB_REF)[1] ) {
            s = s.replace("*", "-")
            s = s.replace( CB_REF, RECIPE);
            s = s.replace("`R", "");
            let ruleNum = Number( s.replace("`", "").split(RECIPE)[1]);
console.error(">>>RULE in SEE " + ruleNum + " " + s.replace("`", "") + " -> " + ruleNames[ruleNum] );
            s = s.replace("`", ":");
            s += ' ' + ruleNames[ruleNum];
        }

        mdText.push( s );

        if( doc_lines[_line].startsWith(CB_SEE) )
                    _line++;
		_line++;
	}

    mdText.push("");

	return "";
}


//
// Main routine
//
let commandLineArgs = process.argv.slice(2);
if (commandLineArgs.length === 0) {
	console.error(">>> Command line error: no arguments");
	process.exit(-1);
}
if( commandLineArgs[0] == '-md') {
    commandLineArgs = process.argv.slice(3);
    MAKE_MD = true;
}
let inFileName = commandLineArgs[0];
//console.error(inFileName);
console.log(COPYRIGHT_HEADER);
//console.log("export const cookBookMsg: string[] = []; \n");
//console.log("export const cookBookTag: string[] = []; \n");
console.log( CODE_PROLOGUE );
syncReadFile( inFileName);

for( recNum = 1; recNum < tegs.length; recNum++ ) {
	console.log( "cookBookTag[ " + recNum + " ] = " + STR_DLMTR + ( tegs[ recNum ] ?  tegs[ recNum ] : "" ) + STR_DLMTR + ";" );
}

console.log('\nexport const cookBookRefToFixTitle: Map<number, string> = new Map([');
for (const num of fixTitles.keys()) {
    console.log(`  [${num}, '${fixTitles.get(num)}'],`);
}
console.log(']);');
