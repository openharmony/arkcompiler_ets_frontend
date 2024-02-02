#  Usage of ``ESObject`` type is restricted

Rule ``arkts-limited-esobj``

**Severity: warning**

ArkTS does not allow using ``ESObject`` type in some cases. The most part of
limitations are put in place in order to prevent spread of dynamic objects in
the static codebase. The only scenario where it is permited to use ``ESObject``
as type specifier is in local variable declaration. Initialization of variables
with ``ESObject`` type is also limited. Such variables can only be initialized
with values that originate from interop: other ``ESObject`` typed variables,
any, unknown, variables with anonymous type, etc. It is prohibited to
initialize ``ESObject`` typed variable with statically typed value. Varaible
of type ``ESObject`` can only be passed to interop calls and assigned to other
variables of type ``ESObject``.


## ArkTS


```
    // lib.d.ts
    declare function foo(): any;
    declare function bar(a: any): number;

    // main.ets
    let e0: ESObject = foo(); // CTE - ``ESObject`` typed variable can only be local

    function f() {
        let e1 = foo(); // CTE - type of e1 is `any`
        let e2: ESObject = 1; // CTE - can't initialize ESObject with not dynamic values
        let e3: ESObject = {}; // CTE - can't initialize ESObject with not dynamic values
        let e4: ESObject = []; // CTE - can't initialize ESObject with not dynamic values
        let e5: ESObject = ""; // CTE - can't initialize ESObject with not dynamic values
        e5['prop'] // CTE - can't access dynamic properties of ESObject
        e5[1] // CTE - can't access dynamic properties of ESObject
        e5.prop // CTE - can't access dynamic properties of ESObject

        let e6: ESObject = foo(); // OK - explicitly annotaded as ESObject
        let e7 = e6; // OK - initialize ESObject with ESObject
        bar(e7) // OK - ESObject is passed to interop call
    }
```


## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 137:  ``globalThis`` is not supported (``arkts-no-globalthis``)

