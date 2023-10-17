#  ``import default as ...`` is not supported

Rule ``arkts-no-import-default-as``

**Severity: error**

ArkTS does not support ``import default as ...`` syntax.
Use explicit ``import ... from ...`` instead.


## TypeScript


```

    import { default as d } from "mod"

```

## ArkTS


```

    import d from "mod"

```


