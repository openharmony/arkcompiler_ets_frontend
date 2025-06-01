### How to run bindings test?

```Bash
cd /path/to/bindings

### check environment, replace the path base on your machine
# if you are using Linux shell
bash test/prepare.sh
# or if you are using Windows shell
powershell -f test/prepare.ps1

### run test
npm install
npm run test

### restore the path to the original state
bash test/prepare.sh --restore
# or
powershell -f test/prepare.ps1 --restore
```

#### tips
1. If you want to update a lot of expected results, you can use `node dist-test/test/run_tests.js ./test --update`

### testcase directory structure
.
├── expected
│   ├── exampleFuncName.json
└── testcases
    ├── .idea
    │   └── .deveco
    │       ├── exampleFuncName
    │       │   └── arktsconfig.json
    │       ├── lsp_build_config.json
    │       └── lsp_compileFileInfos.json
    ├── cases.json
    └── exampleFuncName
        └── exampleFuncName1.ets

case.json:
```json
{
   "testName": {
      "expectedFilePath": "/path/to/expected.json",
      "1": [ "param1", "param2" ], // lsp will call lsp.testName(param1, param2)
      "2": [ "param1", "param2" ]
   }
}
```

#### How to add a new test case?
1. add exampleFuncName2.ets file in `testcases/exampleFuncName`
2. add parameters in `testcases/cases.json`
3. add expected result in `expected/exampleFuncName.json`

#### How to add a new test function?
1. add exampleFuncName2 directory in `testcases`
2. add exampleFuncName2 field in `testcases/cases.json`
3. add exampleFuncName2.json in `expected`
4. add a new test case according to the above steps

⚠️⚠️⚠️
Before push your code, please make sure that the path formats in all JSON files under the testcases directory are correct.
Incorrect path formats will render the function of prepare.sh ineffective, and manually handling the paths can be quite annoying.