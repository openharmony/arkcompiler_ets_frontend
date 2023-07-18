import fs from 'fs';
import path from 'path';
import assert from 'assert';

const filePath = path.join(__filename, '../namespace_api_use.ts');
const actual = fs.readFileSync(filePath, 'utf-8');

const expectation = `import moduleName01 from './namespace_api_01';
moduleName01.Entry.ADDRESS;
moduleName01.Entry.NUMBER;
moduleName01.NewDocument.PARAMETER02;
moduleName01.NewDocument.PARAMETER01;`

assert.strictEqual(actual.trim(), expectation.trim());