# ``this`` typing is supported only for methods with explicit ``this`` return

Rule ``arkts-this-typing``

**Severity: error**

ArkTS allows type notation using the ``this`` keyword only for a return type
of an instance method of a class or struct.
Such methods can only return ``this`` explicitly (``return this``).

## TypeScript


```
    class C {
        n: number = 0

        m(c: this) {
            console.log(c)
        }

        foo(): this {
            return this.bar();
        }

        bar(): this {
            return this;
        }
    }

```

## ArkTS


```
    class C {
        n: number = 0

        m(c: C) {
            console.log(c)
        }

        foo(): this {
            return this;
        }

        bar(): this {
            return this;
        }
    }

```


