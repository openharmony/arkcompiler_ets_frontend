#  Classes cannot be specified in ``implements`` clause

Rule ``arkts-implements-only-iface``

**Severity: error**

ArkTS does not allow to specify a class in implements clause. Only interfaces
may be specified.


## TypeScript


```

    class C {
      foo() {}
    }

    class C1 implements C {
      foo() {}
    }

```

## ArkTS


```

    interface C {
      foo(): void
    }

    class C1 implements C {
      foo() {}
    }

```


