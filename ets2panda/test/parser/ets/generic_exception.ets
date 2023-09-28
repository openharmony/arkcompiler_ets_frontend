class E<T> extends Exception {}

function main(): int {
    try {
        throw new E<Long>();
    } catch (e: E<Long>) {
        return 0;
    } catch (e: E<String>) {
        return 0;
    } catch (e) {
        return 0;
    }
    return 0;
}
