function getProperty<out, Key extends keyof out>(obj: out, key: Key) {
    return obj[key];
}