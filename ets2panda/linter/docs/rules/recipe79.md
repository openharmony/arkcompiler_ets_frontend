#  Type annotation in catch clause is not supported

Rule ``arkts-no-types-in-catch``

**Severity: error**

In TypeScript, catch clause variable type annotation must be ``any`` or ``unknown``
if specified. As ArkTS does not support these types, omit type annotations.


## TypeScript


```

    try {
        // some code
    }
    catch (a: unknown) {
        // handle error
    }

```

## ArkTS


```

    try {
        // some code
    }
    catch (a) {
        // handle error
    }

```

## See also

- Recipe 087:  ``throw`` statements cannot accept values of arbitrary types (``arkts-limited-throw``)


