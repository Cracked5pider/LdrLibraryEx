#include <LdrLibraryEx.h>
#include <stdio.h>

BOOL ApiSetLoad(
    VOID
);

int wmain(
    int       argc,
    wchar_t** argv
) {
    printf( "press enter to start..." );
    getchar();

    //
    // map and test against advapi32.dll
    //
    puts( "[*] trying to resolve api set" );
    if ( ! ApiSetLoad() ) {
        puts( "[-] failed to resolve and load api set" );
    }
    puts( "[*] finished" );

    return 0;
}

BOOL ApiSetLoad(
    VOID
) {
    BOOL     Success = FALSE;
    NTSTATUS Status  = STATUS_SUCCESS;
    PVOID    Module  = { 0 };
    ULONG    Flags   = { 0 };

    //
    // mapping flags to be used by the library
    // and insert the loaded module into Peb
    //
    Flags = LIBRARYEX_NONE;

    //
    // map file into memory
    //
    if ( ! NT_SUCCESS( Status = LdrLibrary(
        L"api-ms-win-base-util-l1-1-0.dll",
        &Module,
        Flags
    ) ) ) {
        printf( "[-] LdrLibraryEx Failed: %p\n", Status );
        goto END;
    }

    printf( "[*] Module @ %p\n", Module );

    Success = TRUE;

END:
    return Success;
}
