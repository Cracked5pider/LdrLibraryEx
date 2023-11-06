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

PVOID ReadFileBuffer(
    LPWSTR Path,
    PDWORD MemorySize
);

int wmain(
    int       argc,
    wchar_t** argv
) {
    printf( "press enter to start..." );
    getchar();

    puts( "[*] trying to load cryptsp.dll" );
    if ( ! MapCryptSp() ) {
        puts( "[-] failed to load & test cryptsp.dll" );
    }
    puts( "[*] finished" );

    return 0;
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
    BOOL     Success   = { 0 };
    NTSTATUS Status    = { 0 };
    PVOID    Module    = { 0 };
    ULONG    Flags     = { 0 };
    PVOID    Sys32     = { 0 };
    CSTRING  CKey      = { 0 };
    CSTRING  CDat      = { 0 };
    PVOID    Image     = { 0 };
    CHAR     Dat[]     = { 0x01, 0x01, 0x01, 0x01 };
    CHAR     Key[]     = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    //
    // mapping flags to be used by the library
    // and insert the loaded module into Peb
    //
    Flags = LIBRARYEX_BYPASS_LOAD_CALLBACK |
            LIBRARYEX_BUFFER               |
            LIBRARYEX_NO_ENTRY;

    //
    // read file on disk into memory
    //
    if ( ! ( Image = ReadFileBuffer( L"C:\\Windows\\System32\\cryptsp.dll", NULL ) ) ) {
        puts( "[-] ReadFileBuffer Failed" );
        goto END;
    }

    //
    // map file into memory
    //
    if ( ! NT_SUCCESS( Status = LdrLibrary(
        Image,
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
    if ( Image ) {
        LocalFree( Image );
        Image = NULL;
    }

    return Success;
}

PVOID ReadFileBuffer(
    _In_  LPWSTR Path,
    _Out_ PDWORD MemorySize
) {
    PVOID  ImageBuffer = { 0 };
    DWORD  dwBytesRead = { 0 };
    HANDLE hFile       = { 0 };
    ULONG  Size        = { 0 };

    if ( ( hFile = CreateFileW( Path, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 ) ) == INVALID_HANDLE_VALUE ) {
        printf( "CreateFileA Failed: %ld\n", GetLastError() );
        return NULL;
    }

    Size = GetFileSize( hFile, 0 );

    if ( MemorySize ) {
        *MemorySize = Size;
    }

    if ( ( ImageBuffer = LocalAlloc( LPTR, Size ) ) ) {
        ReadFile( hFile, ImageBuffer, Size, &dwBytesRead, 0 );
    }

    CloseHandle( hFile );

    return ImageBuffer;
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