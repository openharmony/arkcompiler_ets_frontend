#  No decorators except ArkUI decorators are currently allowed

Rule ``arkts-no-decorators-except-arkui``

**Severity: warning**

Currently, only ArkUI decorators are allowed  in the ArkTS.
Any other decorator will cause a compile-time error.


## TypeScript


```

    function classDecorator(x: any, y: any): void {
        //
    }

    @classDecorator
    class BugReport {
    }


```

## ArkTS


```

    function classDecorator(x: any, y: any): void {
        //
    }

    @classDecorator // compile-time error: unsupported decorator
    class BugReport {
    }

```


