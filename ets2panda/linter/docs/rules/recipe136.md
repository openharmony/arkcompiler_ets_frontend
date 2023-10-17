#  Prototype assignment is not supported

Rule ``arkts-no-prototype-assignment``

**Severity: error**

ArkTS does not support prototype assignment because there is no concept of
runtime prototype inheritance in the language. This feature is considered not
applicable to static typing. Mechanism of classes and / or interfaces must
be used instead to statically "combine" methods to data together.


## TypeScript


```

    var C = function(p: number) {
        this.p = p // Compile-time error only with noImplicitThis
    }

    C.prototype = {
        m() {
            console.log(this.p)
        }
    }

    C.prototype.q = function(r: number) {
        return this.p == r
    }

```

## ArkTS


```

    class C {
        p: number = 0
        m() {
            console.log(this.p)
        }
        q(r: number) {
            return this.p == r
        }
    }

```

## See also

- Recipe 132:  ``new.target`` is not supported (``arkts-no-new-target``)


