/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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


let json = JSON.parse("[ 1, 2, 3]");
print(json,[1,2,3]);
let json2 = JSON.parse("[       1       ]");
print(json2,[1]);
let json3 = JSON.parse("[              ]");
print(json3,[]);
let data = {
    "11111111" : "https://www.a.com",
    "22222222" : "https://www.b.com",
    "00000000" : "https://www.c.com"
}
let strData = JSON.stringify(data);
let res = JSON.parse(strData);
print(res["11111111"],'https://www.a.com');
print(res["22222222"],'https://www.b.com');
print(res["00000000"],'https://www.c.com');

var a = `{"code": 0, "msg": "ok"}`
function reviver(k, v) { return v; }
var o = JSON.parse(a, reviver);
print(o.toString(),'[object Object]');

let strData2 = "1.7976971348623157e+308";
let res2 = JSON.parse(strData2);
print(res2,Infinity);

let strData3 = "-1.7976971348623157e+308";
let res3 = JSON.parse(strData3);
print(res3,-Infinity);

let strData4 = "123";
let res4 = JSON.parse(strData4);
print(res4,123);

try {
    JSON.parse(`{"object": 42, "test":{}`)
} catch (error) {
    print(error.name,'SyntaxError')
    
}

let strData5 = "\"\\uDC00\"";
let res5 = JSON.parse(strData5);
print(res5.codePointAt(0),56320)

let strData6 = '{"a": "{\\"width\\": 18}"}'
print(JSON.stringify(JSON.parse(strData6)),'{"a":"{\\"width\\": 18}"}')

let strData7 = '{"a": "{\\"name\\": \\"张三\\"}"}'
print(JSON.stringify(JSON.parse(strData7)),'{"a":"{\\"name\\": \\"张三\\"}"}')

let strData8 = '{"1\\u0000":"name"}'
print(JSON.stringify(JSON.parse(strData8)),'{"1\\u0000":"name"}')

print(JSON.parse('123.456e-789'),0);
print(1 / JSON.parse('-0'),-Infinity);

var string = "JSON.parse with backslash";
print(string,"JSON.parse with backslash");
print(JSON.parse('"\\"\\""'),'""');  // utf8 -> utf8
print(JSON.parse('"\\u0055\\u0066"'),'Uf');  // utf8 -> utf8
print(JSON.parse('"\\u5555\\u6666"'),'啕晦');  // utf8 -> utf16
print(JSON.parse('["\\"\\"","中文"]')[0],'""');  // utf16 -> utf8
print(JSON.parse('["\\u0055\\u0066","中文"]')[0],'Uf');  // utf16 -> utf8
print(JSON.parse('["\\u5555\\u6666","中文"]')[0],'啕晦');  // utf16 -> utf16

const strData9 = `{"k1":"hello","k2":3}`;
const strErr = strData9.substring(0, strData9.length - 2);
try {
    JSON.parse(strErr);
} catch (err) {
    print(err.name,'SyntaxError');
}

const strData10 = `{"k1":"hello","k2":                    3}`;
const strErr2 = strData10.substring(0, strData10.length - 2);
try {
    JSON.parse(strErr2);
} catch (err) {
    print(err.name,'SyntaxError');
}

const strData11 = `{"k1":"hello","k2":311111}`;
const strErr3 = strData11.substring(0, strData11.length - 2);
try {
    JSON.parse(strErr3);
} catch (err) {
    print(err.name,'SyntaxError');
}

let jsonSingleStr = `{
    "a": 10,
    "b": "hello",
    "c": true,
    "d": null,
	"e": 5,
	"f": 6,
	"g": 7,
	"h": 8,
	"i": 9,
	"j": 10,
	"k": 11,
	"l": 12,
	"m": 13,
	"n": 14,
	"o": 15,
	"p": 16,
	"q": 17,
	"r": 18,
	"s": 19,
	"t": 20,
	"u": 21,
	"v": 22,
	"w": 23,
	"x": 24,
	"y": 25,
	"z": 26,
	"A": 27,
	"B": 28,
	"C": 29,
	"D": 30,
	"E": 31,
	"F": 32,
	"G": 33,
	"H": 34,
	"I": 35,
	"J": 36,
	"K": 37,
	"L": 38,
	"M": 39,
	"N": 40,
	"O": 41,
	"P": 42,
	"Q": 43,
	"R": 44,
	"S": 45,
	"T": 46,
	"U": 47,
	"V": 48,
	"W": 49,
	"X": 50,
	"Y": 51,
	"Z": 52
}`;

let parsedObj = JSON.parse(jsonSingleStr);
print(parsedObj.a, 10);
print(parsedObj.b, 'hello');
print(parsedObj.c, true);
print(parsedObj.n, 14);
print(parsedObj.x, 24);
print(parsedObj.C, 29);
print(parsedObj.J, 36);
print(parsedObj.T, 46);

let numStr = `{
    "numberval1": 1.79e+308,
    "numberval2": 1.7976931348623158e+309,
    "numberval3": 5e+320,
    "numberval4": 2.225e-308,
	"numberval5": 2.225e-309,
	"numberval6": 3e-320,
	"numberval7": 5e-324,
	"numberval8": 5e-325,
	"numberval9": 7e-350
}`;
let numParsedObj = JSON.parse(numStr);
print(numParsedObj.numberval1, 1.79e+308);// DBL_MAX
print(numParsedObj.numberval2, Infinity);// greater than DBL_MAX, expect Infinity
print(numParsedObj.numberval3, Infinity);// greater than DBL_MAX, expect Infinity
print(numParsedObj.numberval4, 2.225e-308);// DBL_MIN
print(numParsedObj.numberval5, 2.225e-309);// less than DBL_MIN
print(numParsedObj.numberval6, 3e-320);// less than DBL_MIN
print(numParsedObj.numberval7, 5e-324);// Number.MIN_VALUE
print(numParsedObj.numberval8, 0);// less than Number.MIN_VALUE, expect 0
print(numParsedObj.numberval9, 0);// less than Number.MIN_VALUE, expect 0

print(2.225e-308); // 2.225e-308
print(2.225e-309); // 2.225e-309
print(3e-320);     // 3e-320
print(5e-324);     // 5e-324

{
	let err = {};
	try {
		JSON.parse(`{"object哈哈": 42, "test":{}`)
	} catch (error) {
		err = error;
	}
	print(err.name, 'SyntaxError');
}