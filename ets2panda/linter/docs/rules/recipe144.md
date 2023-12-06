#  Usage of standard library is restricted

Rule ``arkts-limited-stdlib``

**Severity: error**

ArkTS does not allow using some APIs from the TypeScript/JavaScript standard library.
The most part of the restricted APIs relates to manipulating objects in a
dynamic manner, which is not compatible with static typing. The usage of
the following APIs is prohibited:

Properties and functions of the global object: ``eval``

``Object``: ``__proto__``, ``__defineGetter__``, ``__defineSetter__``,
``__lookupGetter__``, ``__lookupSetter__``, ``assign``, ``create``,
``defineProperties``, ``defineProperty``, ``freeze``,
``fromEntries``, ``getOwnPropertyDescriptor``, ``getOwnPropertyDescriptors``,
``getOwnPropertySymbols``, ``getPrototypeOf``,
``hasOwnProperty``, ``is``, ``isExtensible``, ``isFrozen``,
``isPrototypeOf``, ``isSealed``, ``preventExtensions``,
``propertyIsEnumerable``, ``seal``, ``setPrototypeOf``

``Reflect``: ``apply``, ``construct``, ``defineProperty``, ``deleteProperty``,
``getOwnPropertyDescriptor``, ``getPrototypeOf``, ``isExtensible``,
``preventExtensions``, ``setPrototypeOf``

``Proxy``: ``handler.apply()``, ``handler.construct()``,
``handler.defineProperty()``, ``handler.deleteProperty()``, ``handler.get()``,
``handler.getOwnPropertyDescriptor()``, ``handler.getPrototypeOf()``,
``handler.has()``, ``handler.isExtensible()``, ``handler.ownKeys()``,
``handler.preventExtensions()``, ``handler.set()``, ``handler.setPrototypeOf()``


## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 137:  ``globalThis`` is not supported (``arkts-no-globalthis``)


