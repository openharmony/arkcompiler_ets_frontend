#  Reassigning object methods is not supported

Rule ``arkts-no-method-reassignment``

**Severity: error**

ArkTS does not support re-assigning a method for objects. In the statically
types languages, the layout of objects is fixed and all instances of the same
object must share the same code of each method.

If you need to add specific behavior for certain objects, you can create
separate wrapper functions or use inheritance.


## TypeScript


```

    class C {
        foo() {
            console.log("foo")
        }
    }

    function bar() {
        console.log("bar")
    }

    let c1 = new C()
    let c2 = new C()
    c2.foo = bar

    c1.foo() // foo
    c2.foo() // bar

```

## ArkTS


```

    class C {
        foo() {
            console.log("foo")
        }
    }

    class Derived extends C {
        foo() {
            console.log("Extra")
            super.foo()
        }
    }

    function bar() {
        console.log("bar")
    }

    let c1 = new C()
    let c2 = new C()
    c1.foo() // foo
    c2.foo() // foo

    let c3 = new Derived()
    c3.foo() // Extra foo

```


