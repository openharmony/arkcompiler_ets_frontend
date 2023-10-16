@Component
struct HideComponent {
    build() {
        Column() {
            Text('goodbye')
                // @ts-ignore
                .fontColor(Color.Blue)
        }
    }
}
