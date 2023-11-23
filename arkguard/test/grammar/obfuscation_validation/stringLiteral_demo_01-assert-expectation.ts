import fs from 'fs';
import path from 'path';
import assert from 'assert';

const filePath = path.join(__filename, '../stringLiteral_demo_01_use.ts');
const actual = fs.readFileSync(filePath, 'utf-8').toString();

const expectation = `const stringLiteralObj02 = {
    "'": 1,
    '"': 2,
    '\\\\': 3,
    '\\b': 4,
    '\\f': 5,
    '\\n': 6,
    '\\r': 7,
    '\\t': 8,
    '\\v': 9,
    '\\0': 10,
    '\\u2028': 11,
    '\\u2029': 12,
};`

assert.strictEqual(actual.trim(), expectation.trim());