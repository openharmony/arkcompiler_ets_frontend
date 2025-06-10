# ArkTS1.2 build system test suite

The test suite bases on [Jest](https://jestjs.io/) and aims to test the `build_system`.

---

## Import Jest && Test Suite

### 1. Edit the build_system/package.json file

**Add test scripts**  
Add the following to the `scripts` section in `package.json`(already in the code repository):

```json
"scripts": {
  "build_system_Utest": "jest --testMatch='**/test/ut/**/utils.test.ts' --testPathIgnorePatterns='test/e2e/'", 
  "build_system_Etest": "TEST=${test_script_name} jest test/e2e/compile.test.ts",
}
```

Build_system_Utest is for unit tests while build_system_Etest is for E2E tests. 
The `TEST` environment variable is used to specify the test script to run for E2E tests.

**Add dependencies**  
Add the following to the `devDependencies` section in `package.json`(already in the code repository):

```json
"devDependencies": {
  "@babel/core": "^7.27.1", 
  "@babel/preset-env": "^7.27.2",
  "@babel/preset-typescript": "^7.27.1",
  "@types/jest": "^29.5.14",
  "babel-jest": "^29.7.0",
  "jest": "^29.7.0",
  "ts-node": "^10.9.2"
}
```

**Babel configuration**

Babel allows running tests without compiling test files with tsc first.  
Add the following to `package.json`(already in the code repository):

```json
"babel": {
  "presets": [
    ["@babel/preset-env", { "targets": { "node": "current" } }],
    "@babel/preset-typescript"
  ]
}
```

### 2. Jest configuration

Add the following to `build_system/jest.config.js`(already in the code repository):

```js
module.exports = {
  testEnvironment: "node",
  verbose: true,
  collectCoverage: true,
  coverageDirectory: "<rootDir>/dist/coverage",
  setupFilesAfterEnv: [
    "<rootDir>/testHook/jest.memory-usage.js",
    "<rootDir>/testHook/jest.time-usage.js",
    "<rootDir>/testHook/jest.abc-size.js"
  ],
  testMatch: [
    "<rootDir>/test/ut/**/*.test.[jt]s"
  ],
  testPathIgnorePatterns: []
};
```

---

## Running the Test Suite

Before running the test suite, ensure that the build_system itself can be compiled locally.
End-to-end tests depend on the SDK. It is recommended to copy the SDK directly into `build_system/test/mock_sdk` and replace the original three folders.  
After replacing the SDK, grant execute permissions to all files under `build_system/test/mock_sdk/build-tools/ets2panda/bin` and export the `LD_LIBRARY_PATH` environment variable.  
Replace the SDK → grant execute permissions to bin/* → update paths → install dependencies via npm → run npm scripts → compile src successfully.

1. Enter the `build_system` directory

   ```bash
   cd ${absolute_path_to_build_system}
   ```

2. Perform mock_sdk operations to ensure that the build_system itself and hap packages can be compiled locally:
  
   Copy the SDK for Linux (`ets/ets1.2/*`) to `build_system/test/mock_sdk`.  
   After copying, the mock_sdk directory should contain the folders `api`, `arkts`, `build-tools`, and `kits`.

   Grant execute permissions to the executables under `mock_sdk/build-tools/ets2panda/bin`:
   ```bash
   chmod +x test/mock_sdk/build-tools/ets2panda/bin/*
   ```

   Replace all `${absolute_path_to_build_system}` in e2e test code with the actual directory:
   ```bash
   find test -name 'build_config*.json' -exec sed -i 's|${absolute_path_to_build_system}|'"$(pwd)"'|g' {} +
   find test -name 'decl-fileInfo.json' -exec sed -i 's|${absolute_path_to_build_system}|'"$(pwd)"'|g' {} +
   ```

   Export the `LD_LIBRARY_PATH` environment variable. To avoid exporting it every time, you can add it to your environment file. Be sure to replace with the actual directory:
   ```bash
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${absolute_path_to_build_system}/test/mock_sdk/build-tools/ets2panda/lib
   ```

   Install dependencies and compile all files under `src`:
   
   ```bash
   npm install
   npm run build
   ```

3. **[optional]** Customize the test suite by modifying Jest parameters in `jest.config.js`, such as including or excluding test files:

   ```js
   module.exports = {
     testEnvironment: "node",
     verbose: true,
     collectCoverage: true,
     coverageDirectory: "<rootDir>/coverageReport",
     setupFilesAfterEnv: [
       "<rootDir>/testHook/jest.memory-usage.js"
       // "<rootDir>/testHook/jest.time-usage.js"
     ],
     testMatch: [
       "test/ut/sum.test.ts"
     ], 
     testPathIgnorePatterns: [
       "/test/ut/skip/", 
       "/test/ut/sometest.test.ts"
     ]
   }
   ```

---

## Unit Test Example

Add an `osType.test.ts` file under `build_system/test/ut`:

```typescript
import { isWindows, isLinux, isMac } from '../../src/utils';

describe('osType', () => {
  it('should detect OS type correctly', () => {
    expect(isWindows()).toBe(false);
    expect(isLinux()).toBe(true);
    expect(isMac()).toBe(false);
  });
});
```

Run from the command line:

```bash
npm run build_system_Utest
```

#### Recommended Practice

For each test file, create a folder with the same name under `ut`. For example, for `osType.test.ts`, create a `ut/osType` folder. using camelCase naming convention.

#### Existing UT
There are corresponding test files for each file under `src`, placed in folders with the same name as in `src`.  
The `mock` folder contains mock files needed for some tests.  
By default, all test files in this directory will be run. You can filter them by adjusting the Jest configuration.

```
ut
├── base_modeTest
│   └── base_mode.test.ts
├── entryTest
│   └── entry.test.ts
├── fileManagerTest
│   └── filemanager.test.ts
├── generate_arktsconfigTest
│   └── generate_arktsconfig.test.ts
├── loggerTest
│   └── logger.test.ts
├── mock
│   └── demo_1.2_dep_hsp1.2
│       ├── build_config.json
│       ├── build_config1.json
│       ├── build_config2.json
│       ├── build_config3.json
│       ├── build_config4.json
│       ├── build_config5.json
│       ├── build_config6.json
│       ├── build_config7.json
│       ├── build_config8.json
│       ├── build_config9.json
│       ├── declgen
│       │   └── default
│       │       ├── declgenBridgeCode
│       │       │   └── entry
│       │       │       ├── Calc.ts
│       │       │       └── index.ts
│       │       └── declgenV1
│       │           └── entry
│       │               ├── Calc.d.ets
│       │               └── index.d.ets
│       ├── entry
│       │   └── a.ets
│       ├── harA
│       │   ├── index.ets
│       │   └── sub.ets
│       └── hspA
│           ├── Calc.ets
│           └── index.ets
├── plugins_driverTest
│   └── plugins_driver.test.ts
├── safeRealpath.test.ts
└── utilsTest
    └── utils.test.ts
```

---

## E2E Test Example

The purpose of end-to-end tests is usually to check whether a project can be compiled, whether the `abc file` is generated correctly, and whether there are errors or exceptions during compilation.  
End-to-end tests are run similarly to unit tests, but with different interface files.

Add a `compile.test.ts` file under `build_system/test/e2e` (The latest version is already in the code repository):

```typescript
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

function getAllModules(config: any) {
  return [
    { packageName: config.packageName, modulePath: config.moduleRootPath, sourceRoots: config.sourceRoots || ['./'] },
    ...(config.dependentModuleList || [])
  ];
}

function getAllSrcFiles(modules: any[]) {
  let allSrcFiles: string[] = [];
  for (const mod of modules) {
    const moduleAbsPath = path.resolve(__dirname, '../../', mod.modulePath || mod.moduleRootPath || '');
    for (const root of mod.sourceRoots || ['./']) {
      const srcRoot = path.resolve(moduleAbsPath, root);
      if (fs.existsSync(srcRoot) && fs.statSync(srcRoot).isDirectory()) {
        const files = fs.readdirSync(srcRoot)
          .filter(f => f.endsWith('.ets'))
          .map(f => path.join(srcRoot, f));
        allSrcFiles = allSrcFiles.concat(files);
      }
    }
  }
  return allSrcFiles;
}

function getModuleNameForSrc(src: string, allModuleNames: string[], defaultName: string): string | undefined {
  for (const mod of allModuleNames) {
    if (src.includes(`/${mod}/`)) return mod;
  }
  return defaultName;
}

function testHelper(testDir: string) {
  const configPath = path.resolve(__dirname, '../..', testDir, 'build_config.json');
  if (!fs.existsSync(configPath)) {
    throw new Error(`Missing ${configPath}`);
  }

  const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  const cachePath = path.resolve(__dirname, '../../', config.cachePath);

  const allModuleNames = [
    config.packageName,
    ...(config.dependentModuleList?.map((dep: any) => dep.packageName) || [])
  ];

  const expectedOutputs = config.compileFiles.map((src: string) => {
    const moduleName = getModuleNameForSrc(src, allModuleNames, config.packageName);
    const baseName = path.basename(src, path.extname(src));
    return path.join(cachePath, moduleName, `${baseName}.abc`);
  });

  describe('Check Compilation Outputs', () => {
    beforeAll(() => {
      execSync(`node ./dist/entry.js ${configPath}`, { stdio: 'inherit' });
    });

    it('Check outputs for compiled files', () => {
      expectedOutputs.forEach(filePath => {
        if (!fs.existsSync(filePath)) {
          throw new Error(`Not found: ${filePath}`);
        }
        if (fs.statSync(filePath).size === 0) {
          throw new Error(`${filePath} is empty`);
        }
      });
    });

    it('Check outputs for non-compiled source files', () => {
      const modules = getAllModules(config);
      const allSrcFiles = getAllSrcFiles(modules);
      const compiledSet = new Set(
        config.compileFiles.map((cf: string) => path.resolve(__dirname, '../../', cf))
      );
      const notCompiled = allSrcFiles.filter(f => !compiledSet.has(f));
      notCompiled.forEach(srcFile => {
        const moduleName = getModuleNameForSrc(srcFile, allModuleNames, config.packageName);
        const baseName = path.basename(srcFile, path.extname(srcFile));
        const outputFile = path.join(cachePath, moduleName, `${baseName}.abc`);
        if (fs.existsSync(outputFile)) {
          throw new Error(`Non-compiled source file ${srcFile} generated output ${outputFile}`);
        }
      });
    });
  });

  afterAll(() => {
    execSync(`rimraf ${cachePath}`, { stdio: 'inherit' });
  });
}

const testDir = process.env.TEST;
if (!testDir) {
  throw new Error('Test folder not found');
} else if (testDir === 'all') {
  const baseDir = path.resolve(__dirname, '../../test');
  const dirs = fs.readdirSync(baseDir)
    .map(name => path.join('test', name))
    .filter(dir => fs.statSync(path.resolve(__dirname, '../..', dir)).isDirectory())
    .filter(dir => fs.existsSync(path.resolve(__dirname, '../..', dir, 'build_config.json')));
  if (dirs.length === 0) {
    throw new Error('No tests found');
  }
  for (const dir of dirs) {
    testHelper(dir);
  }
} else {
  testHelper(testDir);
}
```
Since the project under test may be very complex, with multiple `build_config.json` files and unknown compilation order, users are required to write scripts to specify the compilation process.  
Usage:

   Modify the `build_system_Etest` script's TEST parameter to the test project script:
  
   ```json
   "scripts": {
    "entry1_2_external_har1_2:gen_abc": "npm run build && node ./dist/entry.js ${absolute_path_to_build_system}/test/e2e/entry1_2_external_har1_2/build_config.json",
     "build_system_Etest": "TEST=entry1_2_external_har1_2:gen_abc jest --testMatch '${absolute_path_to_build_system}/test/e2e/*.test.ts'"
   }
   ```

   Specify the full script name after TEST=.

   Run from the command line:

   ```bash
   npm run build_system_Etest
   ```

   This will execute the test.

To add tests,  create a new test file/folder under `build_system/test/e2e`. The `build_system_Etest` script will automatically include the test.
   
---

## How to Write Tests

The test suite is based on Jest, using Jest's assertions and matcher mechanisms.

### Global Configuration

- Group tests: `describe(name, fn)`, multiple tests are included in fn as a group.
- Single test: `it(name, fn)`, fn contains the test implementation. All `it` can be replaced with the alias `test`.
- Failing test: `it.failing(name, fn, timeout)`, opposite of `it`: if fn succeeds, the test fails; if fn fails, the test passes.
- Todo: `it.todo(name)`, indicates the test is not yet written.
- Run before/after all tests: `afterAll(fn, timeout)`, `beforeAll(fn, timeout)`, fn is the implementation, optional timeout.
- Run before/after each test: `afterEach(fn, timeout)`, `beforeEach(fn, timeout)`, fn is the implementation, optional timeout.

### Assertions

`expect(expr)` creates an assertion object, e.g.`expect(isLinux())`

### Matchers

Matchers are methods provided by assertion objects and can be chained (method chaining). Jest provides many matchers; here are some common ones:

- `toBe(value)`: Checks if values are equal
- `toHaveBeenCalled()`: Checks if a function was called, often used with mock functions
- `toHaveReturned()`: Checks if a function returned normally, often used with mock functions
- `toHaveLength(number)`: Checks array length
- `toBeInstanceOf(Class)`: Checks if an object is an instance of a class (like `instanceof`)
- `toContain(item)`: Checks for containment
- etc. See [official documentation](https://jestjs.io/docs/expect) for more matchers.

### Mock Functions

Example: Add an `osType.test.ts` file under `build_system/test/ut/osType`:

```typescript
import * as utils from '../../src/utils';

describe('osTypeCheck', () => {
  it('should detect OS type correctly', () => {
    expect(utils.isWindows()).toBe(false);
    expect(utils.isLinux()).toBe(true);
    expect(utils.isMac()).toBe(false);
  });
  it('mocked isWindows always return true', () => {
    const spy = jest.spyOn(utils, 'isWindows').mockImplementation(() => true);
    expect(utils.isWindows()).toBe(true);
    expect(utils.isLinux()).toBe(true);
    expect(utils.isMac()).toBe(false);
    spy.mockRestore();
  });
});
```

Note: ES6 imports are read-only and cannot be modified, so you must use `import * as utils` to import the module.  
Whether to mock the whole module or just a function depends on the specific situation.  
Mock functions provide many interfaces for assertions and checks. See [official documentation](https://jestjs.io/docs/mock-function-api).


### Asynchronous Code

Functions that return a Promise can be tested directly. If they return `Promise.resolve()`, the test passes; if they return `Promise.reject()`, the test fails.

### Results

Test results are printed to the command line by default.

Example (may change in the future):

```
console.log
    [Jest][osTypeCheck should detect OS type correctly] Peak memory change: 0.28 MB

      at Object.log (testHook/jest.memory-usage.js:12:11)

  console.log
    [Jest][osTypeCheck should detect OS type correctly] Test time: 10 ms

      at Object.log (testHook/jest.time-usage.js:11:11)

  console.log
    [Jest][osTypeCheck mocked isWindows always return true] Peak memory change: 0.28 MB

      at Object.log (testHook/jest.memory-usage.js:12:11)

  console.log
    [Jest][osTypeCheck mocked isWindows always return true] Test time: 1 ms

      at Object.log (testHook/jest.time-usage.js:11:11)

 PASS  test/ut/osType/osType.test.ts
  osTypeCheck
    ✓ should detect OS type correctly (11 ms)
    ✓ mocked isWindows always return true (2 ms)
 PASS  test/ut/mockConsoleLog.test.ts
  mockConsoleLog
    ✓ should detect OS type correctly

----------|---------|----------|---------|---------|-------------------
| File       | % Stmts   | % Branch   | % Funcs   | % Lines   | Uncovered Line #s   |
| ---------- | --------- | ---------- | --------- | --------- | ------------------- |
| All files  | 35.29     | 0          | 50        | 35.29     |
| utils.ts   | 35.29     | 0          | 50        | 35.29     | 38-58               |
| ---------- | --------- | ---------- | --------- | --------- | ------------------- |
Test Suites: 2 passed, 2 total
Tests:       3 passed, 3 total
Snapshots:   0 total
Time:        0.668 s, estimated 1 s
Ran all test suites.
```

The table is a summary of coverage, showing statement, branch, function, and line coverage for each file.  
Test Suites is the number of test files executed.  
Tests is the number of test/it blocks in the test files.  
Since there may be command line output during compilation, it is recommended to redirect the output stream, for example, by outputting compilation information to a temporary file.

---

## New Folder Structure

```
build_system
├── dist                    # Compiled output directory
│   └── coverage            # Coverage output directory
├── src                     # Source code directory
├── test                    # Test directory
│   ├── ut                  # Unit tests
│   │   ├── mockOsType               # Mock function tests
│   │   │   └── mockOsType.test.ts   # Mock OS type test
│   │   ├── mockConsoleLog.test.ts   # Mock console.log test
│   │   └── ...                      # More unit tests
│   └── e2e                 # End-to-end tests
│       ├── compile.test.ts          # Compilation test
│       ├── abcGenerationTest        # Example hap project
│       └── ...                      # More end-to-end tests
├── testHook                # Test hook files
│   ├── jest.memory-usage.js         # Memory usage monitoring
│   ├── jest.time-usage.js           # Test time monitoring
│   └── jest.abc-size.js             # abc file size monitoring
├── package.json            # Project configuration file
└── jest.config.js          # Jest configuration file
```

---

## Coverage Report

A summary of coverage information is printed to the command line.  
A detailed coverage report is output to the `dist/coverage` directory by default. You can change the output path by modifying the `coverageDirectory` field in `jest.config.js`.  
Jest uses `Istanbul` to generate coverage reports.  
The coverage report folder includes the following:

```
dist/coverage
├── clover.xml                # Clover format coverage report
├── coverage-final.json       # JSON format coverage report
├── lcov-report               # Detailed HTML coverage report directory
│   ├── base.css
│   ├── block-navigation.js
│   ├── favicon.png
│   ├── index.html            # Coverage report, open in browser for details
│   ├── prettify.css
│   ├── prettify.js
│   ├── sort-arrow-sprite.png
│   └── sorter.js
└── lcov.info                 # Standard LCOV format coverage data file
```

---
