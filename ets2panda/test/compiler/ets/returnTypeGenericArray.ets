interface Iface<T> {
    returnGenericArray(): T[];
}

class Foo<T> implements Iface<T> {
    override returnGenericArray(): T[] {
        return new T[5];
    }
}

