#define LIBRARYEX_PRIVATE
#include <LdrLibraryEx.h>

/*!
 * @brief
 *  load library into memory
 *
 * @param Buffer
 *  buffer context to load library
 *
 * @param Library
 *  loaded library pointer
 *
 * @param Flags
 *  flags
 *
 * @return
 *  status of function
 */
NTSTATUS LdrLibrary(
    _In_  PVOID  Buffer,
    _Out_ PVOID* Library,
    _In_  ULONG  Flags
) {
    LIBRARYEX_CTX Ctx    = { 0 };
    NTSTATUS      Status = { 0 };

    //
    // init context
    // resolving functions and modules
    //
    if ( ! NT_SUCCESS( Status = LdrLibraryCtx( &Ctx, Flags ) ) ) {
        dprintf( "LdrpLibraryCtxInit Failed: %p\n", Status );
        goto END;
    }

    //
    // load library
    //
    if ( ! NT_SUCCESS( Status = LdrLibraryEx( &Ctx, Buffer, Library, Flags ) ) ) {
        dprintf( "LdrLibraryEx Failed: %p\n", Status );
        goto END;
    }

END:
    MemZero( &Ctx, sizeof( Ctx ) );

    return Status;
}

/*!
 * @brief
 *  load library into memory
 *
 * @param Ctx
 *  LibraryEx context
 *
 * @param Buffer
 *  buffer context to load library
 *
 * @param Library
 *  loaded library pointer
 *
 * @param Flags
 *  flags
 *
 * @return
 *  status of function
 */
NTSTATUS LdrLibraryEx(
    _In_  PLIBRARYEX_CTX Ctx,
    _In_  PVOID          Buffer,
    _Out_ PVOID*         Library,
    _In_  ULONG          Flags
) {
    NTSTATUS       Status           = STATUS_UNSUCCESSFUL;
    PVOID          Module           = { 0 };
    UNICODE_STRING Path             = { 0 };
    UNICODE_STRING Name             = { 0 };
    WCHAR          Arry[ MAX_PATH ] = { 0 };
    WCHAR          Resv[ MAX_PATH ] = { 0 };
    ULONG          Size             = { 0 };
    PWSTR          ResName          = { 0 };
    PVOID          Param            = { 0 };

    //
    // Check function arguments
    //
    if ( ! Buffer || ! Library ) {
        Status = STATUS_INVALID_PARAMETER;
        goto END;
    }

    //
    // clear context struct on the stack
    //
    MemZero( Arry, sizeof( Arry ) );
    MemZero( Resv, sizeof( Resv ) );

    Param = Buffer;

    //
    // only do path init if we want to
    // load from file on disk
    //
    if ( ! ( Flags & LIBRARYEX_BUFFER ) ) {
        //
        // check if it's a virtual api set module
        // if yes the resolve the real name module on disk
        //
        if ( LdrpCheckApiSet( Buffer ) ) {
            //
            // looks like we cant find the api set name
            //
            if ( ! NT_SUCCESS( LdrpResolveApiSet( Buffer, &ResName, &Size ) ) ) {
                return STATUS_UNSUCCESSFUL;
            }

            //
            // copy resolved name to a new buffer
            //
            MemCopy( Resv, ResName, Size );
            Param = Resv;

            dprintf( "Resolved api set name %ls -> %ls\n", Buffer, Resv );
        }

        //
        // create path to module
        // trying to load from system32
        //
        if ( ! ( Path.Length = Path.MaximumLength = LdrpInitNtSys32Path( Param, Arry ) ) ) {
            dprintf( "LdrpInitNtSys32Path Failed\n", NULL );
            goto END;
        }
        Path.MaximumLength += sizeof( WCHAR );
        Path.Buffer         = Arry;

        //
        // create unicode objects
        // for BaseDllName
        //
        if ( ! ( Name.Length = Name.MaximumLength = ( LdrpUtilStrLenW( Param ) * sizeof( WCHAR ) ) ) ) {
            goto END;
        }
        Name.MaximumLength += sizeof( WCHAR );
        Name.Buffer         = Param;

        dprintf( "Map into memory :: Name:[%ls :: %hu] Path:[%ls :: %hu]\n", Name.Buffer, Name.Length, Path.Buffer, Path.Length );

        Param = &Path;
    } else {
        dprintf( "Load from memory :: Image @ %p\n", Param );
    }

    //
    // map library into memory
    //
    if ( ! NT_SUCCESS( Status = LdrpLibraryMap( Ctx, Param, Flags, &Module ) ) ) {
        dprintf( "LdrpLibraryMap Failed: %p\n", Status );
        goto END;
    } else dprintf( "Mapped %s into memory @ %p\n", Flags & LIBRARYEX_BUFFER ? NULL : Buffer, Module );

    //
    // process mapped image
    //
    if ( ! NT_SUCCESS( Status = LdrpProcessImg( Ctx, Module, Flags ) ) ) {
        dprintf( "LdrpProcessImg Failed: %p\n", Status );
        goto END;
    } else dprintf( "Successfully processed image [Status: %p]\n", Status );

    //
    // successfully loaded library into memory
    //
    Status   = STATUS_SUCCESS;
    *Library = Module;

END:
    //
    // clear stack memory
    //
    MemZero( Arry,  sizeof( Arry ) );
    MemZero( &Path, sizeof( UNICODE_STRING ) );

    return Status;
}

/*!
 * @brief
 *  resolve function from module
 *
 * @param Library
 *  in memory loaded library pointer
 *
 * @param Function
 *  function to resolve
 *
 * @param Hashed
 *  is the function name param hashed
 *
 * @return
 *  function pointer
 */
PVOID LdrFunctionEx(
    _In_ PVOID Library,
    _In_ PVOID Function,
    _In_ BOOL  Hashed
) {
    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };
    ULONG                   Hash       = { 0 };

    //
    // validate arguments
    //
    if ( ! Library || ! Function ) {
        return NULL;
    }

    //
    // retrieve header of library
    //
    if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
        return NULL;
    }

    //
    // parse the header export address table
    //
    ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
    AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

    //
    // hash given function name to resolve
    //
    Hash = Hashed ? U_PTR( Function ) : LdrHashString( Function, 0 );

    //
    // iterate over export address table director
    //
    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
        FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

        //
        // hash function name from Iat and
        // check the function name is what we are searching for.
        // if not found keep searching.
        //
        if ( LdrHashString( FuncName, 0 ) != Hash ) {
            continue;
        }

        //
        // resolve function pointer
        //
        Address = C_PTR( Library + AddrFuncs[ AddrOrdns[ i ] ] );

        //
        // check if function is a forwarded function
        //
        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            dprintf( "Forwarded function not supported: %s\n", Address );

            //
            // TODO: need to add support for forwarded functions
            //
            __debugbreak();
        }

        break;
    }

    return Address;
}

//
// Private LdrLibraryEx Functions
//

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base pointer to retrieve header from
 *
 * @return
 *  pointer to Nt Header
 */
PIMAGE_NT_HEADERS LdrpImageHeader(
    _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

/*!
 * @brief
 *  init loading library ctx
 *  resolving functions and modules
 *
 * @param Ctx
 *  context
 *
 * @param Flags
 *  flags of methods
 *
 * @return
 *  status of function
 */
NTSTATUS LdrLibraryCtx(
    _Out_ PLIBRARYEX_CTX Ctx,
    _In_  ULONG          Flags
) {
    NTSTATUS Status = { 0 };
    PVOID    Ntdll  = { 0 };
    
    if ( ! Ctx ) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // load ntdll from PEB
    // and resolve functions
    //
    if ( ( Ntdll = LdrModulePeb( C_PTR( H_MODULE_NTDLL ), TRUE ) ) ) {
        //
        // check if we want to load the image into
        // virtual private memory.
        //
        if ( ( Flags & LIBRARYEX_BYPASS_LOAD_CALLBACK ) || ( Flags & LIBRARYEX_BUFFER ) ) {
            //
            // if LIBRARYEX_BUFFER hasn't been specified then it
            // means we want to load the file from disk
            //
            if ( ! ( Flags & LIBRARYEX_BUFFER ) ) {
                Ctx->NtReadFile              = LdrFunctionEx( Ntdll, C_PTR( H_API_NTREADFILE              ), TRUE );
                Ctx->NtQueryInformationFile  = LdrFunctionEx( Ntdll, C_PTR( H_API_NTQUERYINFORMATIONFILE  ), TRUE );
            }

            Ctx->NtAllocateVirtualMemory = LdrFunctionEx( Ntdll, C_PTR( H_API_NTALLOCATEVIRTUALMEMORY ), TRUE );
            Ctx->NtFreeVirtualMemory     = LdrFunctionEx( Ntdll, C_PTR( H_API_NTFREEVIRTUALMEMORY     ), TRUE );
        }

        //
        // map file into memory and back it up
        // by file on disk
        //
        else {
            Ctx->NtCreateSection      = LdrFunctionEx( Ntdll, C_PTR( H_API_NTCREATESECTION      ), TRUE );
            Ctx->NtMapViewOfSection   = LdrFunctionEx( Ntdll, C_PTR( H_API_NTMAPVIEWOFSECTION   ), TRUE );
            Ctx->NtUnmapViewOfSection = LdrFunctionEx( Ntdll, C_PTR( H_API_NTUNMAPVIEWOFSECTION ), TRUE );
        }

        Ctx->NtOpenFile              = LdrFunctionEx( Ntdll, C_PTR( H_API_NTOPENFILE              ), TRUE );
        Ctx->NtProtectVirtualMemory  = LdrFunctionEx( Ntdll, C_PTR( H_API_NTPROTECTVIRTUALMEMORY  ), TRUE );
        Ctx->NtFlushInstructionCache = LdrFunctionEx( Ntdll, C_PTR( H_API_NTFLUSHINSTRUCTIONCACHE ), TRUE );
        Ctx->NtClose                 = LdrFunctionEx( Ntdll, C_PTR( H_API_NTCLOSE                 ), TRUE );
        Ctx->RtlAddFunctionTable     = LdrFunctionEx( Ntdll, C_PTR( H_API_RTLADDFUNCTIONTABLE     ), TRUE );

        //
        // TODO: replace later based on flags
        //
        Ctx->LdrGetProcedureAddress  = LdrFunctionEx( Ntdll, C_PTR( H_API_LDRGETPROCEDUREADDRESS ), TRUE );
        Ctx->LdrLoadDll              = LdrFunctionEx( Ntdll, C_PTR( H_API_LDRLOADDLL             ), TRUE );

    } else {
        Status = STATUS_UNSUCCESSFUL;
    }

    return Status;
}

/*!
 * @brief
 *  map dll into memory
 *
 * @param Ctx
 *  LibraryEx context
 *
 * @param Path
 *  module path to map into memory
 *
 * @param Flags
 *  flags on how to map the image
 *
 * @param Module
 *  mapped module base address
 *
 * @return
 *  success of function
 */
NTSTATUS LdrpLibraryMap(
    _In_  PLIBRARYEX_CTX  Ctx,
    _In_  PVOID           Buffer,
    _In_  ULONG           Flags,
    _Out_ PVOID*          Module
) {
    NTSTATUS          Status           = STATUS_UNSUCCESSFUL;
    HANDLE            File             = { 0 };
    HANDLE            Section          = { 0 };
    PIMG_SEC_HDR      Sec              = { 0 };
    PVOID             Memory           = { 0 };
    OBJECT_ATTRIBUTES ObjAttr          = { 0 };
    IO_STATUS_BLOCK   IoBlock          = { 0 };
    SIZE_T            Length           = { 0 };
    SIZE_T            Size             = { 0 };
    IO_STATUS_BLOCK   IoStatus         = { 0 };
    IO_STATUS_BLOCK   IoStatus2        = { 0 };
    FILE_STD_INFO     FileStdInfo      = { 0 };
    PIMAGE_NT_HEADERS Header           = { 0 };

    if ( ! Ctx || ! Buffer || ! Module ) {
        return STATUS_INVALID_PARAMETER;
    }

    /* zero memory the structs */
    MemZero( &ObjAttr,     sizeof( ObjAttr     ) );
    MemZero( &IoStatus,    sizeof( IoStatus    ) );
    MemZero( &IoStatus2,   sizeof( IoStatus2   ) );
    MemZero( &FileStdInfo, sizeof( FileStdInfo ) );

    //
    // TODO: check if the module name contains an extension
    //       if not then add the ext '.dll' to the module name.
    //

    if ( ! ( Flags & LIBRARYEX_BUFFER ) ) {
        //
        // init object attributes
        //
        InitializeObjectAttributes(
            &ObjAttr,
            Buffer,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
        )

        //
        // open handle to specified file
        //
        if ( ! NT_SUCCESS( Status = Ctx->NtOpenFile(
            &File,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            &ObjAttr,
            &IoBlock,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        ) ) ) {
            dprintf( "NtOpenFile Failed: %p\n", Status );
            goto END;
        }
    }

    //
    // check if we want to load the image into
    // virtual private memory.
    //
    if ( ( Flags & LIBRARYEX_BYPASS_LOAD_CALLBACK ) ||
         ( Flags & LIBRARYEX_BUFFER               )
    ) {
        if ( ! ( Flags & LIBRARYEX_BUFFER ) ) {
            //
            // get size of file
            //
            if ( ! NT_SUCCESS( Status = Ctx->NtQueryInformationFile(
                File,
                &IoStatus,
                &FileStdInfo,
                sizeof( FILE_STANDARD_INFORMATION ),
                FileStandardInformation
            ) ) ) {
                dprintf( "NtQueryInformationFile Failed: %p\n", Status );
                goto END;
            }

            //
            // size of file on disk
            //
            Size = Length = FileStdInfo.AllocationSize.QuadPart;

            //
            // allocate virtual private memory for temporary usage
            //
            if ( ! NT_SUCCESS( Status = Ctx->NtAllocateVirtualMemory(
                NtCurrentProcess(),
                &Memory,
                0,
                &Size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            ) ) ) {
                dprintf( "NtAllocateVirtualMemory Failed: %p\n", Status );
                goto END;
            }

            //
            // read file into virtual private memory
            //
            if ( ! NT_SUCCESS( Status = Ctx->NtReadFile(
                File,
                NULL,
                NULL,
                NULL,
                &IoStatus,
                Memory,
                Length,
                NULL,
                NULL
            ) ) ) {
                dprintf( "NtReadFile Failed: %p\n", Status );
                goto END;
            }
        } else {
            Memory = Buffer;
        }

        //
        // allocate a new virtual private memory
        // based on the Header.OptionalHeader.SizeOfImage and
        // copy the image header and sections
        // to the newly allocated memory
        //

        //
        // retrieve image header
        //
        if ( ! ( Header = LdrpImageHeader( Memory ) ) ) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto END;
        }

        //
        // get size of image to allocate
        //
        Length = Header->OptionalHeader.SizeOfImage;

        //
        // allocate virtual private memory for the file
        //
        if ( ! NT_SUCCESS( Status = Ctx->NtAllocateVirtualMemory(
            NtCurrentProcess(),
            Module,
            0,
            &Length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        ) ) ) {
            dprintf( "NtAllocateVirtualMemory Failed: %p\n", Status );
            goto END;
        }

        //
        // copy over image header
        //
        MemCopy( *Module, Memory, Header->OptionalHeader.SizeOfHeaders );

        //
        // retrieve the first section
        //
        Sec = IMAGE_FIRST_SECTION( Header );

        //
        // iterate over sections and apply protection
        //
        for ( ULONG i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {

            dprintf(
                "copy section [%-8s] :: %p -> %p [%ld]\n",
                Sec[ i ].Name,
                C_PTR( Memory  + Sec[ i ].PointerToRawData ),
                C_PTR( *Module + Sec[ i ].VirtualAddress   ),
                Sec[ i ].SizeOfRawData
            );

            //
            // copy over sections
            //
            MemCopy(
                C_PTR( *Module + Sec[ i ].VirtualAddress   ),
                C_PTR( Memory  + Sec[ i ].PointerToRawData ),
                Sec[ i ].SizeOfRawData
            );
        }

    } else {
        //
        // create section from file handle
        //
        if ( ! NT_SUCCESS( Status = Ctx->NtCreateSection(
            &Section,
            SECTION_ALL_ACCESS,
            NULL,
            NULL,
            PAGE_EXECUTE,
            SEC_IMAGE,
            File
        ) ) ) {
            dprintf( "NtCreateSection Failed: %p\n", Status );
            goto END;
        }

        Length = 0;

        //
        // map section file into memory
        //
        if ( ! NT_SUCCESS( Status = Ctx->NtMapViewOfSection(
            Section,
            NtCurrentProcess(),
            Module,
            0,
            0,
            NULL,
            &Length,
            ViewUnmap,
            0,
            PAGE_READWRITE
        ) ) ) {
            dprintf( "NtMapViewOfSection Failed: %p\n", Status );
            goto END;
        }
    }

    //
    // successful mapped module into memory
    //
    Status = STATUS_SUCCESS;

END:
    //
    // cleanup
    // close file and section handle
    //
    if ( File ) {
        Ctx->NtClose( File );
        File = NULL;
    }

    if ( Section ) {
        Ctx->NtClose( Section );
        Section = NULL;
    }

    //
    // free memory on error
    //
    if ( ! NT_SUCCESS( Status ) && ( Flags & LIBRARYEX_BYPASS_LOAD_CALLBACK || Flags & LIBRARYEX_BUFFER ) ) {

        if ( *Module ) {
            MemZero( *Module, Length );

            //
            // free module memory
            //
            Length = 0;
            if ( ! NT_SUCCESS( Status = Ctx->NtFreeVirtualMemory(
                NtCurrentProcess(),
                Module,
                &Length,
                MEM_RELEASE
            ) ) ) {
                dprintf( "NtFreeVirtualMemory Failed: %p\n", Status );
                goto END;
            }
        }

    }

    if ( Memory && ! ( Flags & LIBRARYEX_BUFFER ) ) {
        MemZero( Memory, Size );

        //
        // free temp memory
        //
        Length = 0;
        if ( ! NT_SUCCESS( Status = Ctx->NtFreeVirtualMemory(
            NtCurrentProcess(),
            &Memory,
            &Length,
            MEM_RELEASE
        ) ) ) {
            dprintf( "NtFreeVirtualMemory Failed: %p\n", Status );
            goto END;
        }
    }

    return Status;
}

/*!
 * @brief
 *  sanity check image
 *
 * @param Hdr
 *  header to check
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpImageSanityCheck(
    _In_ PVOID Hdr
) {
    PIMAGE_NT_HEADERS Header = { 0 };

    if ( ! ( Header = Hdr ) ) {
        return STATUS_INVALID_PARAMETER;
    }

#ifdef _M_X64
    //
    // check arch if we are on x64 and
    // trying to load an x86 image
    //
    if ( Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
#endif

    //
    // check if the image is a .NET module
    // currently not supported
    //
    if ( Header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ].Size ) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

/*!
 * @brief
 *  process image
 *
 *  1. sanity check the image
 *  2. process sections (change protection to RW)
 *  3. perform relocation
 *  4. process import address table
 *  5. process delayed imports
 *  6. process section (restore original protections)
 *  7. process tls

 * @param Ctx
 *  LibraryEx context
 *
 * @param Image
 *  image to process
 *
 * @param Flags
 *  flags
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpProcessImg(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ ULONG          Flags
) {
    NTSTATUS              Status = STATUS_SUCCESS;
    PIMAGE_DATA_DIRECTORY IatDir = { 0 };
    PIMAGE_DATA_DIRECTORY DlyDir = { 0 };
    PIMAGE_DATA_DIRECTORY TlsDir = { 0 };
    PIMAGE_DATA_DIRECTORY RelDir = { 0 };
    PIMAGE_DATA_DIRECTORY SehDir = { 0 };
    PIMAGE_NT_HEADERS     Header = { 0 };
    DLL_ENTRY             Entry  = { 0 };

    //
    // retrieve Nt Header of mapped PE
    //
    if ( ! ( Header = LdrpImageHeader( Image ) ) ) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // sanity check image
    //
    if ( ! NT_SUCCESS( Status = LdrpImageSanityCheck( Header ) ) ) {
        dprintf( "LdrpImageSanityCheck Failed: %p", Status );
        goto END;
    } else dprintf( "Image sanity check passed\n", NULL );

    //
    // apply protection to be able
    // to modify the image sections
    //
    // NOTE:
    //  not needed when the flag
    //  LIBRARYEX_BYPASS_LOAD_CALLBACK has
    //  been specified since the memory
    //  already has been allocated as RW
    //
    if ( ! ( Flags & LIBRARYEX_BYPASS_LOAD_CALLBACK ) ) {
        if ( ! NT_SUCCESS( Status = LdrpProcessSec( Ctx, Image, FALSE ) ) ) {
            dprintf( "LdrpProcessSec Failed: %p\n", Status );
            goto END;
        }
    }

    //
    // retrieve relocation directory pointer
    //
    RelDir = & Header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
    if ( RelDir->VirtualAddress ) {
        //
        // process relocation directory
        //
        LdrpProcessRel(
            Image,
            U_PTR( Header->OptionalHeader.SizeOfImage ),
            C_PTR( Header->OptionalHeader.ImageBase   ),
            C_PTR( U_PTR( Image ) + RelDir->VirtualAddress ),
            RelDir->Size
        );

        dprintf( "Relocation applied\n", NULL );
    } else {
        dprintf( "No relocation director to process\n", NULL );
    }

    //
    // retrieve import address table directory pointer
    //
    IatDir = & Header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
    if ( IatDir->VirtualAddress ) {
        //
        // process import address table
        //
        if ( ! NT_SUCCESS( Status = LdrpProcessIat(
            Ctx,
            Image,
            C_PTR( U_PTR( Image ) + IatDir->VirtualAddress )
        ) ) ) {
            dprintf( "LdrpProcessIat Failed: %p\n", Status );
            goto END;
        } else {
            dprintf( "\n", NULL );
            dprintf( "Import address table processed: [Status: %p]\n", Status );
        }
    } else {
        dprintf( "No imports to process\n", NULL );
    }

    //
    // retrieve delayed import address table directory pointer
    //
    DlyDir = & Header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT ];
    if ( DlyDir->VirtualAddress ) {
        //
        // process delayed import address table
        //
        if ( ! NT_SUCCESS( Status = LdrpProcessDly(
            Ctx,
            Image,
            C_PTR( U_PTR( Image ) + DlyDir->VirtualAddress )
        ) ) ) {
            dprintf( "LdrpProcessDly Failed: %p\n", Status );
            goto END;
        } else {
            dprintf( "\n", NULL );
            dprintf( "Delayed import address table processed: [Status: %p]\n", Status );
        }
    } else {
        dprintf( "No delayed imports to process\n", NULL );
    }

    //
    // retrieve exceptions data directory table pointer
    //
    SehDir = & Header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
    if ( SehDir->VirtualAddress ) {
        //
        // handle exceptions
        //
        if ( ! NT_SUCCESS( Status = LdrpProcessSeh(
            Ctx,
            Image,
            C_PTR( U_PTR( Image ) + SehDir->VirtualAddress )
        ) ) ) {
            dprintf( "LdrpProcessSeh Failed: %p\n", Status );
            goto END;
        } else {
            dprintf( "\n", NULL );
            dprintf( "Exceptions table processed: [Status: %p]\n", Status );
        }
    } else {
        dprintf( "No exceptions to process\n", NULL );
    }

    //
    // restore protection
    //
    if ( ! NT_SUCCESS( Status = LdrpProcessSec( Ctx, Image, TRUE ) ) ) {
        dprintf( "LdrpProcessSec Failed: %p\n", Status );
        goto END;
    } else {
        dprintf( "Processed and restore sections protections: [Status: %p]\n", Status );
    }

    //
    // retrieve tls directory pointer
    //
    TlsDir = & Header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
    if ( TlsDir->VirtualAddress ) {
        //
        // process tls callbacks
        //
        if ( ! NT_SUCCESS( Status = LdrpProcessTls(
            Image,
            C_PTR( U_PTR( Image ) + TlsDir->VirtualAddress )
        ) ) ) {
            dprintf( "LdrpProcessTls Failed: %p\n", Status );
            goto END;
        } else {
            dprintf( "\n", NULL );
            dprintf( "Tls directory table processed: [Status: %p]\n", Status );
        }
    } else {
        dprintf( "No Tls directory to process\n", NULL );
    }

    //
    // execute entrypoint if specified
    // and also check if it's not an executable/exe
    //
    if ( ! ( Flags & LIBRARYEX_NO_ENTRY ) &&
           ( Header->FileHeader.Characteristics & IMAGE_FILE_DLL )
    ) {
        Status = STATUS_DLL_INIT_FAILED;

        //
        // try to get entry pointer
        //
        if ( ! ( Entry = C_PTR( Image ) + Header->OptionalHeader.AddressOfEntryPoint ) ) {
            goto END;
        }

        //
        // execute dll entrypoint
        //
        if ( ! Entry( Image, DLL_PROCESS_ATTACH, NULL ) ) {
            goto END;
        }

        dprintf( "Executed entrypoint @ %p\n", Entry );
    }

#ifdef LIBRARYEX_DEBUG
    //
    // debug print that entry point has not been
    // executed because it is an executable image
    //
    if ( ! ( Flags & LIBRARYEX_NO_ENTRY ) && ! ( Header->FileHeader.Characteristics & IMAGE_FILE_DLL ) ) {
        dprintf( "Did not executed entrypoint. Image is an executable and not a library\n", NULL );
    }
#endif

    //
    // successfully processed image
    //
    Status = STATUS_SUCCESS;

END:
    return Status;
}

/*!
 * @brief
 *  process section protections
 *
 * @param Ctx
 *  LibraryEx context
 *
 * @param Image
 *  image to process sections protection
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpProcessSec(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ BOOL           Restore
) {
    PIMAGE_NT_HEADERS     Header   = { 0 };
    PIMAGE_SECTION_HEADER Section  = { 0 };
    PVOID                 SecBase  = { 0 };
    SIZE_T                SecSize  = { 0 };
    ULONG                 Protect  = { 0 };
    ULONG                 Original = { 0 };
    NTSTATUS              Status   = { 0 };

    //
    // retrieve header of image
    //
    if ( ! ( Header = LdrpImageHeader( Image ) ) ) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    //
    // retrieve the first section
    //
    Section = IMAGE_FIRST_SECTION( Header );

    //
    // iterate over sections and apply protection
    //
    for ( ULONG i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {

        //
        // restore protection from
        // section characteristics
        //
        if ( Restore ) {

            if ( Section->Characteristics & IMAGE_SCN_MEM_READ ) {
                Protect = PAGE_READONLY;
            }

            if ( ( Section->Characteristics & IMAGE_SCN_MEM_WRITE ) &&
                 ( Section->Characteristics & IMAGE_SCN_MEM_READ  )
            ) {
                Protect = PAGE_READWRITE;
            }

            if ( ( Section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) &&
                 ( Section->Characteristics & IMAGE_SCN_MEM_READ    )
            ) {
                Protect = PAGE_EXECUTE_READ;
            }

            if ( ( Section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) &&
                 ( Section->Characteristics & IMAGE_SCN_MEM_WRITE   ) &&
                 ( Section->Characteristics & IMAGE_SCN_MEM_READ    )
            ) {
                Protect = PAGE_EXECUTE_READWRITE;
            }

        } else {
            Protect = PAGE_READWRITE;
        }

        //
        // retrieve section base addr and size
        //
        SecBase = C_PTR( U_PTR( Image ) + Section->VirtualAddress );
        if ( ( SecSize = Section->SizeOfRawData ) ) {
            //
            // apply protection to section
            //
            if ( ! NT_SUCCESS( Status = Ctx->NtProtectVirtualMemory(
                NtCurrentProcess(),
                &SecBase,
                &SecSize,
                Protect,
                &Original
            ) ) ) {
                return Status;
            }
        }

        Section++;
    }

    //
    // flush instruction cache
    //
    if ( Restore ) {
        Ctx->NtFlushInstructionCache( NtCurrentProcess(), NULL, 0 );
    }

    return STATUS_SUCCESS;
}

/*!
 * @brief
 *  process image import address table
 *
 * @param Ctx
 *  LibraryEx context
 *
 * @param Image
 *  image to process
 *
 * @param Dir
 *  image import address table directory
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpProcessIat(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ PVOID          Dir
) {
    NTSTATUS                 Status              = STATUS_SUCCESS;
    PIMAGE_IMPORT_DESCRIPTOR Iat                 = { 0 };
    UNICODE_STRING           UniString           = { 0 };
    ANSI_STRING              AnsString           = { 0 };
    PIMAGE_THUNK_DATA		 OrignThunk          = { 0 };
    PIMAGE_THUNK_DATA		 FirstThunk          = { 0 };
    PVOID                    Module              = { 0 };
    PVOID                    Function            = { 0 };
    SIZE_T                   Size                = { 0 };
    PSTR                     Name                = { 0 };
    WCHAR                    UniName[ MAX_PATH ] = { 0 };
    ULONG                    ResSize             = { 0 };
    PWSTR                    ResName             = { 0 };

    //
    // iterate over the import address table
    //
    for ( Iat = Dir; Iat->Name; Iat++ ) {

        //
        // resolve dll name
        //
        Name = C_PTR( U_PTR( Image ) + Iat->Name );
        Size = LdrpUtilStrLenA( Name );

        //
        // clear previous values from stack
        //
        MemZero( &UniName,   sizeof( UniName   ) );
        MemZero( &UniString, sizeof( UniString ) );
        MemZero( &AnsString, sizeof( AnsString ) );

        //
        // convert ansi string to unicode
        //
        if ( ! LdrpUtilAnsiToUnicode( UniName, Name, Size ) ) {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // try to load it from Peb first
        //
        if ( ! ( Module = LdrModulePeb( UniName, FALSE ) ) ) {
            //
            // check if it's an api set based on
            // the first 4 bytes ("api-" or "ext-")
            //
            if ( LdrpCheckApiSet( UniName ) ) {
                //
                // resolve real module name
                // from virtual api set name
                //
                if ( ! NT_SUCCESS( LdrpResolveApiSet( UniName, &ResName, &ResSize ) ) ) {
                    //
                    // what ever. just use LdrLoadDll then
                    //
                    goto USE_LDRLOADDLL_DLY;
                }

                //
                // get handle to the module from
                // Peb if it already has been loaded
                //
                if ( ! ( Module = LdrModulePeb( ResName, FALSE ) ) ) {

                    UniString.Length         = UniString.MaximumLength = ResSize;
                    UniString.MaximumLength += sizeof( WCHAR );
                    UniString.Buffer         = ResName;

                    //
                    // what ever. just use LdrLoadDll then
                    //
                    goto USE_LDRLOADDLL_DLY;
                }

                dprintf( "\n", NULL );
                dprintf( ":: %s [PEB -> %ls] @ %p\n", Name, ResName, Module );

            } else {

                USE_LDRLOADDLL_DLY:

                //
                // create unicode string object
                // if not already specified above
                //
                if ( ! UniString.Buffer ) {
                    UniString.Length         = UniString.MaximumLength = Size * sizeof( WCHAR );
                    UniString.MaximumLength += sizeof( WCHAR );
                    UniString.Buffer         = UniName;
                }

                //
                // load dll
                // TODO: replace this with our
                //       custom implementation once finished
                //       AND also check if the requested module is already loaded etc.
                //
                if ( ! NT_SUCCESS( Status = Ctx->LdrLoadDll( NULL, 0, &UniString, &Module ) ) ) {
                    dprintf( "LdrLoadDll Failed: %p (DllName: %ls)\n", Status, UniString.Buffer );
                    break;
                }

                MemZero( &UniString, sizeof( UniString ) );
                ResName = NULL;

                dprintf( "\n", NULL );
                dprintf( ":: %s @ %p\n", Name, Module );
            }
        } else {
            dprintf( "\n", NULL );
            dprintf( ":: %s @ %p [PEB]\n", Name, Module );
        }

        //
        // resolve function imports
        //
        if ( Module ) {

            OrignThunk = C_PTR( U_PTR( Image ) + Iat->OriginalFirstThunk );
            FirstThunk = C_PTR( U_PTR( Image ) + Iat->FirstThunk );

            //
            // iterate over function import
            // and resolve them
            //
            for ( ; OrignThunk->u1.AddressOfData; ++OrignThunk, ++FirstThunk ) {

                //
                // check if it's an ordinal.
                // if yes then resolve by ordinal
                // but if not then resolve by name
                //
                if ( IMAGE_SNAP_BY_ORDINAL( OrignThunk->u1.Ordinal ) ) {
                    //
                    // resolve function by ordinal
                    //
                    if ( ! NT_SUCCESS( Status = Ctx->LdrGetProcedureAddress(
                        Module,
                        NULL,
                        IMAGE_ORDINAL( OrignThunk->u1.Ordinal ),
                        &Function
                    ) ) ) {
                        dprintf( "LdrGetProcedureAddress Failed: %p\n", Status );
                        break;
                    }

                } else {
                    //
                    // resolve function name
                    //
                    Name = ( ( PIMAGE_IMPORT_BY_NAME ) C_PTR( U_PTR( Image ) + OrignThunk->u1.AddressOfData ) )->Name;
                    Size = LdrpUtilStrLenA( Name );

                    //
                    // create ansi string object
                    //
                    AnsString.Length        =  AnsString.MaximumLength = Size;
                    AnsString.MaximumLength += sizeof( CHAR );
                    AnsString.Buffer        =  Name;

                    //
                    // resolve function by name
                    //
                    if ( ! NT_SUCCESS( Status = Ctx->LdrGetProcedureAddress(
                        Module,
                        &AnsString,
                        0,
                        &Function
                    ) ) ) {
                        dprintf( "LdrGetProcedureAddress Failed: %p\n", Status );
                        break;
                    }

                    dprintf( " - %p @ %s\n", Function, Name );
                }

                //
                // set resolved function
                //
                FirstThunk->u1.Function = U_PTR( Function );
            }
        }
    }

    return Status;
}

/*!
 * @brief
 *  process delayed imports
 *
 * @param Ctx
 *  LibraryEx context
 *
 * @param Image
 *  image to process
 *
 * @param Dir
 *  delayed import directory
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpProcessDly(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Image,
    _In_ PVOID          Dir
) {
    NTSTATUS                    Status              = STATUS_SUCCESS;
    PIMAGE_DELAYLOAD_DESCRIPTOR Dly                 = { 0 };
    LPSTR                       Name                = { 0 };
    ULONG                       Size                = { 0 };
    WCHAR                       UniName[ MAX_PATH ] = { 0 };
    UNICODE_STRING              UniString           = { 0 };
    ANSI_STRING                 AnsString           = { 0 };
    PVOID                       Module              = { 0 };
    PIMAGE_THUNK_DATA		    OrignThunk          = { 0 };
    PIMAGE_THUNK_DATA		    FirstThunk          = { 0 };
    PVOID                       Function            = { 0 };
    ULONG                       ResSize             = { 0 };
    PWSTR                       ResName             = { 0 };

    //
    // iterate over Delayed import table
    //
    for ( Dly = Dir; Dly->DllNameRVA; Dly++ ) {

        //
        // resolve dll name
        //
        Name = C_PTR( U_PTR( Image ) + Dly->DllNameRVA );
        Size = LdrpUtilStrLenA( Name );

        //
        // clear previous values from stack
        //
        MemZero( &UniName,   sizeof( UniName   ) );
        MemZero( &UniString, sizeof( UniString ) );
        MemZero( &AnsString, sizeof( AnsString ) );

        //
        // convert ansi to unicode
        //
        if ( ! LdrpUtilAnsiToUnicode( UniName, Name, Size ) ) {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // try to load it from Peb first
        //
        if ( ! ( Module = LdrModulePeb( UniName, FALSE ) ) ) {
            //
            // check if it's an api set based on
            // the first 4 bytes ("api-" or "ext-")
            //
            if ( LdrpCheckApiSet( UniName ) ) {
                //
                // resolve real module name
                // from virtual api set name
                //
                if ( ! NT_SUCCESS( LdrpResolveApiSet( UniName, &ResName, &ResSize ) ) ) {
                    //
                    // what ever. just use LdrLoadDll then
                    //
                    goto USE_LDRLOADDLL_DLY;
                }

                //
                // get handle to the module from
                // Peb if it already has been loaded
                //
                if ( ! ( Module = LdrModulePeb( ResName, FALSE ) ) ) {

                    UniString.Length         = UniString.MaximumLength = ResSize;
                    UniString.MaximumLength += sizeof( WCHAR );
                    UniString.Buffer         = ResName;

                    //
                    // what ever. just use LdrLoadDll then
                    //
                    goto USE_LDRLOADDLL_DLY;
                }

                dprintf( "\n", NULL );
                dprintf( ":: %s [PEB -> %ls] @ %p\n", Name, ResName, Module );

            } else {

                USE_LDRLOADDLL_DLY:

                //
                // create unicode string object
                // if not already specified above
                //
                if ( ! UniString.Buffer ) {
                    UniString.Length         = UniString.MaximumLength = Size * sizeof( WCHAR );
                    UniString.MaximumLength += sizeof( WCHAR );
                    UniString.Buffer         = UniName;
                }

                //
                // load dll
                // TODO: replace this with our
                //       custom implementation once finished
                //       AND also check if the requested module is already loaded etc.
                //
                if ( ! NT_SUCCESS( Status = Ctx->LdrLoadDll( NULL, 0, &UniString, &Module ) ) ) {
                    dprintf( "LdrLoadDll Failed: %p (DllName: %ls)\n", Status, UniString.Buffer );
                    break;
                }

                MemZero( &UniString, sizeof( UniString ) );
                ResName = NULL;

                dprintf( "\n", NULL );
                dprintf( ":: %s @ %p\n", Name, Module );
            }
        } else {
            dprintf( "\n", NULL );
            dprintf( ":: %s @ %p [PEB]\n", Name, Module );
        }


        //
        // resolve functions
        //
        if ( Module ) {

            OrignThunk = C_PTR( U_PTR( Image ) + Dly->ImportNameTableRVA    );
            FirstThunk = C_PTR( U_PTR( Image ) + Dly->ImportAddressTableRVA );

            //
            // iterate over function import
            // and resolve them
            //
            for ( ; OrignThunk->u1.AddressOfData; ++OrignThunk, ++FirstThunk ) {

                //
                // check if it's an ordinal.
                // if yes then resolve by ordinal
                // but if not then resolve by name
                //
                if ( IMAGE_SNAP_BY_ORDINAL( OrignThunk->u1.Ordinal ) ) {
                    //
                    // resolve function by ordinal
                    //
                    if ( ! NT_SUCCESS( Status = Ctx->LdrGetProcedureAddress(
                        Module,
                        NULL,
                        IMAGE_ORDINAL( OrignThunk->u1.Ordinal ),
                        &Function
                    ) ) ) {
                        dprintf( "LdrGetProcedureAddress Failed: %p\n", Status );
                        break;
                    }
                } else {
                    //
                    // resolve function name
                    //
                    Name = ( ( PIMAGE_IMPORT_BY_NAME ) C_PTR( U_PTR( Image ) + OrignThunk->u1.AddressOfData ) )->Name;
                    Size = LdrpUtilStrLenA( Name );

                    //
                    // create ansi string object
                    //
                    AnsString.Length        =  AnsString.MaximumLength = Size;
                    AnsString.MaximumLength += sizeof( CHAR );
                    AnsString.Buffer        =  Name;

                    //
                    // resolve function by name
                    //
                    if ( ! NT_SUCCESS( Status = Ctx->LdrGetProcedureAddress(
                        Module,
                        &AnsString,
                        0,
                        &Function
                    ) ) ) {
                        dprintf( "LdrGetProcedureAddress Failed: %p\n", Status );
                        break;
                    }

                    dprintf( " - %p @ %s\n", Function, Name );
                }

                //
                // set resolved function
                //
                FirstThunk->u1.Function = U_PTR( Function );
            }
        }
    }

END:
    return Status;
}

/*!
 * @brief
 *  process tls callbacks
 *
 * @param Image
 *  image to process
 *
 * @param Dir
 *  tls directory
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpProcessTls(
    _In_ PVOID Image,
    _In_ PVOID Dir
) {
    NTSTATUS             Status   = STATUS_SUCCESS;
    PIMAGE_TLS_CALLBACK* Callback = { 0 };
    PIMAGE_TLS_DIRECTORY Tls      = { 0 };

    //
    // sanity check params
    //
    if ( ! Image || ! Dir ) {
        return STATUS_INVALID_PARAMETER;
    }

    Tls = Dir;

    //
    // retrieve tls callbacks
    //
    if ( ( Callback = ( PIMAGE_TLS_CALLBACK* ) Tls->AddressOfCallBacks ) ) {
        //
        // iterate over callback array
        //
        while ( *Callback ) {
            //
            // call tls callback
            //
            ( *Callback )( Image, DLL_PROCESS_ATTACH, NULL );
        }
    }

    return Status;
}

/*!
 * @brief
 *  process image relocation table
 *
 * @param Image
 *  image to process
 *
 * @param Base
 *  image base address to
 *  use for relocation
 *
 * @param Dir
 *  image relocation table directory
 */
VOID LdrpProcessRel(
    _In_ PVOID Image,
    _In_ ULONG ImageSize,
    _In_ PVOID Base,
    _In_ PVOID Dir,
    _In_ ULONG DirSize
) {
    PIMAGE_BASE_RELOCATION BaseRel = { 0 };
    ULONG_PTR              Offset  = { 0 };
    PVOID                  Reloc   = { 0 };
    PVOID                  Address = { 0 };

    //
    // calculate the offset
    //
    Offset  = U_PTR( U_PTR( Image ) - U_PTR( Base ) );
    BaseRel = Dir;

    //
    // iterate over the base relocation table
    //
    while (
        U_PTR( U_PTR( BaseRel ) < U_PTR( U_PTR( Image ) + U_PTR( Dir ) + DirSize ) ) &&
        U_PTR( BaseRel->VirtualAddress != 0 )
    ) {
        Reloc = C_PTR( U_PTR( BaseRel ) + 1 );

        //
        // check if it is not exceeding
        // the size of relocation
        //
        while ( C_PTR( Reloc ) != C_PTR( U_PTR( BaseRel ) + BaseRel->SizeOfBlock ) ) {
            Address = C_PTR( U_PTR( BaseRel->VirtualAddress + ( ( PIMAGE_RELOC ) Reloc )->Offset ) );

            //
            // check if the Rva is within
            // the boundary of the PE image
            //
            if ( U_PTR( Address ) < ImageSize ) {
                //
                // get relocation address to write to
                //
                Address = C_PTR( U_PTR( Image ) + BaseRel->VirtualAddress + ( ( PIMAGE_RELOC ) Reloc )->Offset );

                //
                // perform relocation based on type
                //
                if ( ( ( PIMAGE_RELOC ) Reloc )->Type == IMAGE_REL_BASED_HIGH ) {
                    C_DEF64( Address ) += HIWORD( Offset );
                } else if ( ( ( PIMAGE_RELOC ) Reloc )->Type == IMAGE_REL_BASED_LOW ) {
                    C_DEF64( Address ) += LOWORD( Offset );
                } else if ( ( ( PIMAGE_RELOC ) Reloc )->Type == IMAGE_REL_BASED_DIR64 ) {
                    C_DEF64( Address ) += U_PTR64( Offset );
                } else if ( ( ( PIMAGE_RELOC ) Reloc )->Type == IMAGE_REL_BASED_HIGHLOW ) {
                    C_DEF32( Address ) += U_PTR32( Offset );
                }
            }

            //
            // next relocation
            //
            Reloc++;
        }

        BaseRel = C_PTR( Reloc );
    }
}

/*!
 * @brief
 *  process image and add exceptions
 *  to function table
 *
 * @param Ctx
 *  LibraryEx context
 *
 * @param Img
 *  image base address
 *
 * @param Dir
 *  exception directory table
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpProcessSeh(
    _In_ PLIBRARYEX_CTX Ctx,
    _In_ PVOID          Img,
    _In_ PVOID          Dir
) {
    ULONG Count = { 0 };

    if ( ! Ctx || ! Dir ) {
        return STATUS_INVALID_PARAMETER;
    }

    Count = ( ( ( PIMAGE_DATA_DIRECTORY ) Dir )->Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ) ) - 1;

    if ( Ctx->RtlAddFunctionTable( Dir, Count, U_PTR( Img ) ) ) {
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


BOOL LdrpCheckApiSet(
    _In_ PWSTR Name
) {
    WCHAR Api[ 4 ] = { L'a', L'p', L'i', L'-', NULL };
    WCHAR Ext[ 4 ] = { L'e', L'x', L't', L'-', NULL };

    if ( ( LdrpUtilStrCmpExW( Name, Api, 4 ) == 0 ) ||
         ( LdrpUtilStrCmpExW( Name, Ext, 4 ) == 0 )
    ) {
        return TRUE;
    }

    return FALSE;
}

/*!
 * @brief
 *  resolve api set version 6
 *
 * @param ApiSetName
 *  virtual api set name
 *
 * @param ApiSetRes
 *  resolved api set name
 *
 * @param ResSize
 *  resolved name size
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpResolveApiSetV6(
    _In_  PWSTR  ApiSetName,
    _Out_ PWSTR* ApiSetRes,
    _Out_ PULONG ResSize
) {
    PAPI_SET_NAMESPACE_ARRAY_V6 ApiSetMap = { 0 };
    PAPI_SET_NAMESPACE_ENTRY_V6 ApiEntry  = { 0 };
    PAPI_SET_VALUE_ENTRY_V6     ApiArray  = { 0 };
    PAPI_SET_VALUE_ENTRY_V6     ApiValue  = { 0 };
    PWSTR                       Entry     = { 0 };
    PWSTR                       Value     = { 0 };
    PWSTR                       Name      = { 0 };

    if ( ! ApiSetName || ! ApiSetRes ) {
        return STATUS_INVALID_PARAMETER;
    }

    ApiSetMap = NtCurrentPeb()->ApiSetMap;

    //
    // iterate over api set namespace
    //
    for ( ULONG i = 0; i < ApiSetMap->Count; i++ ) {

        ApiEntry = & ApiSetMap->Array[ i ];
        Entry    = C_PTR( U_PTR( ApiSetMap ) + ApiEntry->NameOffset );
        ApiArray = C_PTR( U_PTR( ApiSetMap ) + ApiEntry->DataOffset );

        //
        // check if it's our virtual api set name
        // if not then get next entry
        //
        if ( LdrpUtilStrCmpExW(
            Entry,
            ApiSetName,
            ApiEntry->Size / sizeof( WCHAR )
        ) != 0 ) {
            continue;
        }

        for ( ULONG j = ApiEntry->Count - 1; j >= 0; j-- ) {

            ApiValue = & ApiArray[ j ];
            Name     = C_PTR( U_PTR( ApiSetMap ) + ApiValue->NameOffset );
            Value    = C_PTR( U_PTR( ApiSetMap ) + ApiValue->ValueOffset );

            if ( ApiValue->NameLength == 0 ) {
                if ( ResSize ) {
                    *ResSize = ApiValue->ValueLength;
                }

                *ApiSetRes = Value;

                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_NOT_FOUND;
}

/*!
 * @brief
 *  resolve api set name
 *
 * @param ApiSetName
 *  vitual api set name
 *
 * @param ApiSetRes
 *  resolved api set name
 *
 * @param ResSize
 *  resolved name size
 *
 * @return
 *  status of function
 */
NTSTATUS LdrpResolveApiSet(
    _In_  PWSTR  ApiSetName,
    _Out_ PWSTR* ApiSetRes,
    _Out_ PULONG ResSize
) {
    PAPI_SET_NAMESPACE_ARRAY_V2 ApiSetMap = { 0 };
    NTSTATUS                    Status    = { 0 };

    if ( ! ApiSetName || ! ApiSetRes ) {
        return STATUS_INVALID_PARAMETER;
    }

    ApiSetMap = NtCurrentPeb()->ApiSetMap;

    //
    // for now only support v6 for win10 only.
    //
    if ( ApiSetMap->Version == API_SET_VERSION_V6 ) {
        Status = LdrpResolveApiSetV6( ApiSetName, ApiSetRes, ResSize );
    } else {
        Status = STATUS_NOT_SUPPORTED;
    }

    return Status;
}

/*!
 * @brief
 *  resolve module from peb
 *
 * @param Buffer
 *  Buffer: either string or hash
 *
 * @param Hashed
 *  is the Buffer a hash value
 *
 * @return
 *  module base pointer
 */
PVOID LdrModulePeb(
    _In_ PVOID Buffer,
    _In_ BOOL  Hashed
) {
    PLDR_DATA_TABLE_ENTRY Data  = NULL;
    PLIST_ENTRY           Head  = NULL;
    PLIST_ENTRY           Entry = NULL;

    /* Get pointer to list */
    Head  = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    /* iterate over list */
    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        /* Compare the DLL Name! */
        if ( Hashed ) {
            if ( LdrHashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == U_PTR( Buffer ) ) {
                return Data->DllBase;
            }
        } else {
            if ( LdrpUtilStrCmpExW( Data->BaseDllName.Buffer, Buffer, Data->BaseDllName.Length ) == 0 ) {
                return Data->DllBase;
            }
        }

    }

    return NULL;
}

/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
ULONG LdrHashString(
    _In_ PVOID String,
    _In_ ULONG Length
) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Hash = H_MAGIC_KEY;
    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        /* turn current character to uppercase */
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        /* append hash */
        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SIZE_T LdrpUtilStrLenA(
    _In_ PCSTR String
) {
    PCSTR String2;

    for ( String2 = String; *String2; ++String2 );

    return ( String2 - String );
}

SIZE_T LdrpUtilStrLenW(
    _In_ PCWSTR String
) {
    PCWSTR String2;

    for ( String2 = String; *String2; ++String2 );

    return ( String2 - String );
}

SIZE_T LdrpUtilStrCmpW(
    _In_ LPCWSTR String1,
    _In_ LPCWSTR String2
) {
    for ( ; *String1 == *String2; String1++, String2++ ) {
        if ( *String1 == '\0' ) return 0;
    }

    return ( ( * ( LPCWSTR ) String1 < * ( LPCWSTR ) String2 ) ? -1 : +1 );
}

SIZE_T LdrpUtilStrCmpExW(
    _In_ PWSTR String1,
    _In_ PWSTR String2,
    _In_ ULONG  Size
) {
    PWSTR s1 = { 0 };
    PWSTR s2 = { 0 };
    WCHAR c1 = { 0 };
    WCHAR c2 = { 0 };

    if ( ! ( s1 = String1 ) || ! ( s2 = String2 ) ) {
        return -1;
    }

    while ( Size-- )
    {
        c1 = *s1;
        c2 = *s2;

        if ( c1 >= 'a' ) {
            c1 -= 0x20;
        }

        if ( c2 >= 'a' ) {
            c2 -= 0x20;
        }

        if ( c1 != c2 ) {
            return ( c1 - c2 );
        }

        if ( ! c1 ) {
            return 0;
        }

        ++s1;
        ++s2;
    }

    return 0;

}

SIZE_T LdrpUtilAnsiToUnicode(
    _Out_ PWCHAR Destination,
    _In_  PCHAR  Source,
    _In_  SIZE_T MaximumAllowed
) {
    SIZE_T Length = MaximumAllowed;

    while ( --Length >= 0 ) {
        if ( ! ( *Destination++ = *Source++ ) ) {
            return MaximumAllowed - Length - 1;
        }
    }

    return MaximumAllowed - Length;
}

/*!
 * @brief
 *  creates an Nt system32 path based
 *  on the specified name
 *
 * @param Name
 *  name to append to the nt system32 path
 *
 * @param Path
 *  output of the nt system32 full name path
 *
 * @return
 *  size of Path buffer
 */
ULONG LdrpInitNtSys32Path(
    _In_  LPWSTR Name,
    _Out_ LPWSTR Path
) {
    ULONG Length   = { 0 };
    WCHAR System[] = { L'\\', L'?', L'?', L'\\', L'C', L':', L'\\', L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\', L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\' };

    //
    // retrieve & check module name size
    //
    if ( ! ( Length = ( LdrpUtilStrLenW( Name ) * sizeof( WCHAR ) ) ) ) {
        return 0;
    }

    //
    // copy over the system32
    // path + module name to the buffer
    //
    MemCopy( Path, System, sizeof( System ) );
    MemCopy( C_PTR( U_PTR( Path ) + sizeof( System ) ), Name, Length );

END:
    MemZero( System, sizeof( System ) );

    return ( sizeof( System ) + Length );
}

/*!
 * @brief
 *  sanity check if the specified path
 *  is in the Nt path syntax
 *
 * @param Path
 *  path to check
 *
 * @param Sanitised
 *  sanitised string. should be size of
 *  specified Path + ( 4 * sizeof( WCHAR ) )
 *
 * @return
 *  if non zero then path has been sanitised
 *  if NULL then no change applied
 */
ULONG LdrpSanityCheckNtPath(
    _In_  LPWSTR Path,
    _Out_ LPWSTR Sanitised
) {
    ULONG Size = { 0 };

    //
    // check passed arguments
    // if they are non-zero
    //
    if ( ! Path || ! Sanitised ) {
        return 0;
    }

    //
    // check if string starts with \??\
    //
    if ( Path[ 0 ] == L'\\' && Path[ 1 ] == L'?'  &&
         Path[ 2 ] == L'?'  && Path[ 3 ] == L'\\'
    ) {
        //
        // if it does then no change is required
        //
        return 0;
    }

    //
    // create sanitised path
    //
    if ( ( Size = ( LdrpUtilStrLenW( Path ) * sizeof( WCHAR ) ) ) ) {
        Sanitised[ 0 ] = L'\\';
        Sanitised[ 1 ] = L'?';
        Sanitised[ 2 ] = L'?';
        Sanitised[ 3 ] = L'\\';

        MemCopy( Sanitised + ( 4 * sizeof( WCHAR ) ), Path, Size );
        Size += 4 * sizeof( WCHAR );
    }

    return Size;
}