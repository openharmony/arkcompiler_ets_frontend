#  Type notation using ``this`` is not supported

Rule ``arkts-no-typing-with-this``

**Severity: error**

ArkTS does not support type notation using the ``this`` keyword (for example,
specifying a method's return type ``this`` is not allowed). Use explicit type
instead.


## TypeScript


```

    interface ListItem {
        getHead(): this
    }

    class C {
        n: number = 0

        m(c: this) {
            console.log(c)
        }
    }

```

## ArkTS


```

    interface ListItem {
        getHead(): ListItem
    }

    class C {
        n: number = 0

        m(c: C) {
            console.log(c)
        }
    }

```


