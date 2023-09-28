    // Declaration:
    declare module "*!text" {
        const content: string
        export default content
    }

    // Consuming code:
    import fileContent from "some.txt!text"