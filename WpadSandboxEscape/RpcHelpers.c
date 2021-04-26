#include <Windows.h>

////////
////////
// RPC helpers
////////

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes) { // https://docs.microsoft.com/en-us/windows/desktop/Rpc/the-midl-user-allocate-function
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr) { // https://docs.microsoft.com/en-us/windows/desktop/Rpc/the-midl-user-free-function
    free(ptr);
}