#ifndef LDRLIBRARYEX_LDRLIBRARYEX_H
#define LDRLIBRARYEX_LDRLIBRARYEX_H

#include <Native.h>
#include <windows.h>

//
// LdrLibraryEx Flags
//
#define LIBRARYEX_NONE                  0b00000000 // just load it into memory and execute it
#define LIBRARYEX_RESERVED0             0b00000001 // reserved 0
#define LIBRARYEX_BYPASS_LOAD_CALLBACK  0b00000010 // bypass image load callbacks by allocating the module in a virtual private memory
#define LIBRARYEX_RESERVED1             0b00000100 // reserved 1
#define LIBRARYEX_NO_ENTRY              0b00001000 // do not execute the entrypoint
#define LIBRARYEX_BUFFER                0b00010000 // load image from memory/buffer
#define LIBRARYEX_RESERVED2             0b00100000 // reserved 2

//
// LdrLibraryEx defines and macros
//
#define C_PTR( x )          ( ( PVOID )     x )
#define U_PTR( x )          ( ( ULONG_PTR ) x )
#define U_PTR32( x )        ( ( ULONG32 ) x )
#define U_PTR64( x )        ( ( ULONG64 ) x )
#define C_DEF64( x )        ( *( ULONG64* ) x )
#define C_DEF32( x )        ( *( ULONG32* ) x )

#define LdrFunction( m, f ) LdrFunctionEx( m, ( ( LPSTR ) f ), FALSE )
#define WIN32_FUNC( x )     __typeof__( x ) * x;
#define MemCopy             __builtin_memcpy
#define MemSet              __stosb
#define MemZero( b, s )     MemSet( ( PUCHAR ) b, 0, s )

//
// Context
//
typedef struct _LIBRARYEX_CTX {

    /* Nt functions */
    WIN32_FUNC( NtOpenFile )
    WIN32_FUNC( NtReadFile )
    WIN32_FUNC( NtQueryInformationFile )
    WIN32_FUNC( NtCreateSection )
    WIN32_FUNC( NtMapViewOfSection )
    WIN32_FUNC( NtUnmapViewOfSection )
    WIN32_FUNC( NtAllocateVirtualMemory )
    WIN32_FUNC( NtFreeVirtualMemory )
    WIN32_FUNC( NtProtectVirtualMemory )
    WIN32_FUNC( NtFlushInstructionCache )
    WIN32_FUNC( NtClose )

    /* Ldr functions */
    WIN32_FUNC( LdrGetProcedureAddress )
    WIN32_FUNC( LdrLoadDll )

    /* Rlt functions */
    WIN32_FUNC( RtlAddFunctionTable )

} LIBRARYEX_CTX, *PLIBRARYEX_CTX;


//
// Public LdrLibraryEx Functions
//
NTSTATUS LdrLibrary(
    _In_  PVOID  Buffer,
    _Out_ PVOID* Library,
    _In_  ULONG  Flags
);

NTSTATUS LdrLibraryCtx(
    _Out_ PLIBRARYEX_CTX Ctx,
    _In_  ULONG          Flags
);

NTSTATUS LdrLibraryEx(
    _In_  PLIBRARYEX_CTX Ctx,
    _In_  PVOID          Buffer,
    _Out_ PVOID*         Library,
    _In_  ULONG          Flags
);

PVOID LdrModulePeb(
    _In_ PVOID Buffer,
    _In_ BOOL  Hashed
);

ULONG LdrHashString(
    _In_ PVOID String,
    _In_ ULONG Length
);

PVOID LdrFunctionEx(
    _In_ PVOID Library,
    _In_ PVOID Function,
    _In_ BOOL  Hashed
);

//
// Private LdrLibraryEx Functions
//
#ifdef LIBRARYEX_PRIVATE

#define H_MAGIC_KEY       5381

/* modules */
#define H_MODULE_NTDLL    0x70e61753

/* apis */
#define H_API_NTOPENFILE                0x46dde739
#define H_API_NTREADFILE                0xb2d93203
#define H_API_NTQUERYINFORMATIONFILE    0xc25ebe23
#define H_API_NTQUERYSYSTEMTIME         0x4d80f0d1
#define H_API_NTCREATESECTION           0xb80f7b50
#define H_API_NTMAPVIEWOFSECTION        0xd6649bca
#define H_API_NTUNMAPVIEWOFSECTION      0x6aa412cd
#define H_API_NTALLOCATEVIRTUALMEMORY   0xf783b8ec
#define H_API_NTFREEVIRTUALMEMORY       0x2802c609
#define H_API_NTPROTECTVIRTUALMEMORY    0x50e92888
#define H_API_NTFLUSHINSTRUCTIONCACHE   0x6269b87f
#define H_API_NTCLOSE                   0x40d6e69d
#define H_API_LDRGETPROCEDUREADDRESS    0xfce76bb6
#define H_API_LDRLOADDLL                0x9e456a43
#define H_API_RTLALLOCATEHEAP           0x3be94c5a
#define H_API_RTLFREEHEAP               0x73a9e4d7
#define H_API_RTLADDFUNCTIONTABLE       0x81a887ce

//
// some defines
//
#define HASH_STRING_ALGORITHM_DEFAULT  0
#define HASH_STRING_ALGORITHM_X65599   1
#define HASH_STRING_ALGORITHM_INVALID  0xffffffff

//
// structs
//
typedef struct
{
    WORD Offset	: 0xc;
    WORD Type	: 0x4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOLEAN ( * DLL_ENTRY ) (
    _In_        PVOID,
    _In_        ULONG,
    _Inout_opt_ PVOID
);

typedef FILE_STANDARD_INFORMATION FILE_STD_INFO;
typedef PIMAGE_SECTION_HEADER     PIMG_SEC_HDR;

PIMAGE_NT_HEADERS LdrpImageHeader(
    _In_ PVOID Image
);

NTSTATUS LdrpLibraryMap(
    _In_  PLIBRARYEX_CTX  Ctx,
    _In_  PVOID           Buffer,
    _In_  ULONG           Flags,
    _Out_ PVOID*          Module
);

NTSTATUS LdrpImageSanityCheck(
    _In_ PVOID Hdr
);

NTSTATUS LdrpProcessImg(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ ULONG          Flags
);

NTSTATUS LdrpProcessSec(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ BOOL           Restore
);

NTSTATUS LdrpProcessIat(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ PVOID          Dir
);

NTSTATUS LdrpProcessDly(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ PVOID          Dir
);

NTSTATUS LdrpProcessTls(
    _In_ PVOID Image,
    _In_ PVOID Dir
);

VOID LdrpProcessRel(
    _In_ PVOID Image,
    _In_ ULONG ImageSize,
    _In_ PVOID Base,
    _In_ PVOID Dir,
    _In_ ULONG DirSize
);

NTSTATUS LdrpProcessSeh(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Img,
    _In_ PVOID          Dir
);

BOOL LdrpCheckApiSet(
    _In_ PWSTR Name
);

NTSTATUS LdrpResolveApiSet(
    _In_  PWSTR  ApiSetName,
    _In_  PWSTR* ApiSetRes,
    _Out_ PULONG ResSize
);

ULONG LdrpInitNtSys32Path(
    _In_  LPWSTR Name,
    _Out_ LPWSTR Path
);

ULONG LdrpSanityCheckNtPath(
    _In_  LPWSTR Path,
    _Out_ LPWSTR Sanitised
);

//
// Util functions
//

SIZE_T LdrpUtilStrLenA(
    _In_ PCSTR String
);

SIZE_T LdrpUtilStrLenW(
    _In_ PCWSTR String
);

SIZE_T LdrpUtilStrCmpW(
    _In_ LPCWSTR String1,
    _In_ LPCWSTR String2
);

SIZE_T LdrpUtilStrCmpExW(
    _In_ PWSTR String1,
    _In_ PWSTR String2,
    _In_ ULONG Size
);

SIZE_T LdrpUtilAnsiToUnicode(
    _Out_ PWCHAR Destination,
    _In_  PCHAR  Source,
    _In_  SIZE_T MaximumAllowed
);

#endif

#ifdef LIBRARYEX_DEBUG

#include <stdio.h>
#define dprintf( f, ... ) printf( "[%s:%04d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ )

#else

#define dprintf( f, ... ) { ; }

#endif

typedef struct _API_SET_VALUE_ENTRY_V6
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, *PAPI_SET_VALUE_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_HASH_ENTRY_V6
{
    ULONG Hash;
    ULONG Index;
} API_SET_NAMESPACE_HASH_ENTRY_V6, *PAPI_SET_NAMESPACE_HASH_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG Size;
    ULONG NameLength;
    ULONG DataOffset;
    ULONG Count;
} API_SET_NAMESPACE_ENTRY_V6, *PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_ARRAY_V6
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG DataOffset;
    ULONG HashOffset;
    ULONG Multiplier;
    API_SET_NAMESPACE_ENTRY_V6 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V6, *PAPI_SET_NAMESPACE_ARRAY_V6;

typedef struct _API_SET_VALUE_ENTRY_V4
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4
{
    ULONG Flags;
    ULONG Count;
    API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, *PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, *PAPI_SET_NAMESPACE_ARRAY_V4;

typedef struct _API_SET_VALUE_ENTRY_V2
{
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2
{
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2
{
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2
{
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;

#define API_SET_VERSION_V6  6
#define API_SET_VERSION_V4  4
#define API_SET_VERSION_V2  2

#endif
