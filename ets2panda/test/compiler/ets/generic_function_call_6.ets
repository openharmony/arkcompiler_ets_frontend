class A {}
class B {}

function fn<T extends A>() {}

function main() {
    fn<B>()
}
