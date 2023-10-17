#  RegExp literals are not supported

Rule ``arkts-no-regexp-literals``

**Severity: error**

Currently, ArkTS does not support RegExp literals. Use library call with
string literals instead.


## TypeScript


```

    let regex: RegExp = /bc*d/

```

## ArkTS


```

    let regex: RegExp = new RegExp("/bc*d/")

```


