#define LIBRARYEX_DEBUG

#include <LdrLibraryEx.h>
#include <stdio.h>

VOID PrintBytes(
    _In_ LPSTR    Name,
    _In_ PCSTRING Data
);

BOOL MapRunDll32(
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
    puts( "[*] trying to load rundll32.exe" );
    if ( ! MapRunDll32() ) {
        puts( "[-] failed to load & test rundll32.exe" );
    }
    puts( "[*] finished" );

    return 0;
}

/*!
 * @brief
 *  load rundll32 into memory
 *
 * @return
 */
BOOL MapRunDll32(
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
        L"rundll32.exe",
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
