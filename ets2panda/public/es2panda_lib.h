#ifndef ES2PANDA_LIB
#define ES2PANDA_LIB

#ifdef __cplusplus
extern "C" {
#endif

// Switch off the linter for C header
// NOLINTBEGIN

#define ES2PANDA_LIB_VERSION 0

typedef void es2panda_Config;
typedef void es2panda_Context;

enum es2panda_ContextState {
    ES2PANDA_STATE_NEW,
    ES2PANDA_STATE_PARSED,
    ES2PANDA_STATE_CHECKED,
    ES2PANDA_STATE_LOWERED,
    ES2PANDA_STATE_ASM_GENERATED,
    ES2PANDA_STATE_BIN_GENERATED,

    ES2PANDA_STATE_ERROR
};
typedef enum es2panda_ContextState es2panda_ContextState;

struct es2panda_Impl {
    int version;

    es2panda_Config *(*CreateConfig)(int argc, char const **argv);
    void (*DestroyConfig)(es2panda_Config *config);

    es2panda_Context *(*CreateContextFromFile)(es2panda_Config *config, char const *source_file_name);
    es2panda_Context *(*CreateContextFromString)(es2panda_Config *config, char const *source, char const *file_name);
    es2panda_Context *(*ProceedToState)(es2panda_Context *context, es2panda_ContextState state);  // context is consumed
    void (*DestroyContext)(es2panda_Context *context);

    es2panda_ContextState (*ContextState)(es2panda_Context *context);
    char const *(*ContextErrorMessage)(es2panda_Context *context);
};

struct es2panda_Impl const *es2panda_GetImpl(int version);
// NOLINTEND

#ifdef __cplusplus
}
#endif

#endif  // ES2PANDA_LIB
