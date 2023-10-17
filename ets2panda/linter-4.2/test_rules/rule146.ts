    // @ts-nocheck
    // ...
    // Some code with switched off type checker
    // ...

    let s1: string = null // No error, type checker suppressed

    // @ts-ignore
    let s2: string = null // No error, type checker suppressed