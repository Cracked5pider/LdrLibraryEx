#define LIBRARYEX_DEBUG

#include <LdrLibraryEx.h>
#include <stdio.h>

VOID PrintBytes(
    _In_ LPSTR    Name,
    _In_ PCSTRING Data
);

BOOL MapCryptSp(
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
    puts( "[*] trying to load cryptsp.dll" );
    if ( ! MapCryptSp() ) {
        puts( "[-] failed to load & test cryptsp.dll" );
    }
    puts( "[*] finished" );

    return 0;
}

//
// lazy hook example
//
NTSTATUS NTAPI HookLdrLoadDll(
    _In_opt_ PWCHAR          PathToFile,
    _In_opt_ ULONG           Flags,
    _In_     PUNICODE_STRING ModuleFileName,
    _Out_    PHANDLE         ModuleHandle
) {
    NTSTATUS ( *pLdrLoadDll )(
        _In_opt_ PWCHAR          PathToFile,
        _In_opt_ ULONG           Flags,
        _In_     PUNICODE_STRING ModuleFileName,
        _Out_    PHANDLE         ModuleHandle
    ) = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( ( pLdrLoadDll = C_PTR( GetProcAddress( GetModuleHandleA( "ntdll" ), "LdrLoadDll" ) ) ) ) {
        printf( "[*] Hook called: LdrLoadDll( %ls, %ld, %ls, %p ) -> ", PathToFile, Flags, ModuleFileName->Buffer, ModuleHandle );

        Status = pLdrLoadDll( PathToFile, Flags, ModuleFileName, ModuleHandle );

        printf( "%p\n", Status );
    }

    return Status;
}

/*!
 * @brief
 *  load cryptsp into memory and test some functions
 *
 * @return
 */
BOOL MapCryptSp(
    VOID
) {
    LIBRARYEX_CTX Ctx     = { 0 };
    BOOL          Success = { 0 };
    NTSTATUS      Status  = { 0 };
    PVOID         Module  = { 0 };
    ULONG         Flags   = { 0 };
    PVOID         Sys32   = { 0 };
    CSTRING       CKey    = { 0 };
    CSTRING       CDat    = { 0 };
    CHAR          Dat[]   = { 0x01, 0x01, 0x01, 0x01 };
    CHAR          Key[]   = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    //
    // mapping flags to be used by the library
    // and insert the loaded module into Peb
    //
    Flags = LIBRARYEX_BYPASS_LOAD_CALLBACK |
            LIBRARYEX_NO_ENTRY;

    //
    // init LibraryEx context
    //
    if ( ! NT_SUCCESS( Status = LdrLibraryCtx( &Ctx, Flags ) ) ) {
        printf( "LdrLibraryCtx Failed: %d\n", Status );
        goto END;
    }

    //
    // hook function
    //
    Ctx.LdrLoadDll = C_PTR( HookLdrLoadDll );

    //
    // map file into memory
    //
    if ( ! NT_SUCCESS( Status = LdrLibraryEx(
        &Ctx,
        L"cryptsp.dll",
        &Module,
        Flags
    ) ) ) {
        printf( "[-] LdrLibraryEx Failed: %p\n", Status );
        goto END;
    }

    //
    // test functions
    //
    if ( ( Sys32 = LdrFunction( Module, "SystemFunction032" ) ) ) {

        CKey.Length = CKey.MaximumLength = sizeof( Key );
        CKey.Buffer = Key;

        CDat.Length = CKey.MaximumLength = sizeof( Dat );
        CDat.Buffer = Dat;

        PrintBytes( "Data", &CDat );

        ( ( NTSTATUS( * ) ( PCSTRING, PCSTRING ) ) Sys32 )( &CDat, &CKey );
        PrintBytes( "Data", &CDat );
        ( ( NTSTATUS( * ) ( PCSTRING, PCSTRING ) ) Sys32 )( &CDat, &CKey );

        PrintBytes( "Data", &CDat );

    } else puts( "[-] Failed to load SystemFunction032" );

    printf( "[*] Module @ %p\n", Module );

    Success = TRUE;

END:
    return Success;
}

VOID PrintBytes(
    _In_ LPSTR    Name,
    _In_ PCSTRING Data
) {
    printf( "[*] %s :: [ ", Name );

    for ( USHORT i = 0; i < Data->Length; i++ ) {
        printf( "%x " , Data->Buffer[ i ] );
    }

    puts( "]" );
}