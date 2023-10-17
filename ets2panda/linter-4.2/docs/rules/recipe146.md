#  Switching off type checks with in-place comments is not allowed

Rule ``arkts-strict-typing-required``

**Severity: error**

Type checker in ArkTS is not optional, the code must be explicitly and
correctly typed to be compiled and run. "Suppressing" type checker in-place
with special comments is not allowed. In particular, ``@ts-ignore`` and
``@ts-nocheck`` annotations are not supported.


## TypeScript


```

    // @ts-nocheck
    // ...
    // Some code with switched off type checker
    // ...

    let s1: string = null // No error, type checker suppressed

    // @ts-ignore
    let s2: string = null // No error, type checker suppressed

```

## ArkTS


```

    let s1: string | null = null // No error, properly types
    let s2: string = null // Compile-time error

```

## See also

- Recipe 008:  Use explicit types instead of ``any``, ``unknown`` (``arkts-no-any-unknown``)
- Recipe 145:  Strict type checking is enforced (``arkts-strict-typing``)


