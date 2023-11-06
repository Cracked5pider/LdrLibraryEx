
# LdrLibraryEx

A small x64 library to load dll's into memory. 

### Features
- low dependencies & function use (only ntdll.dll used)
- position independent code 
- lightweight and minimal
- easy to use
- load modules from memory 
- load modules from disk 
- api sets support
- bypass image load callbacks (using private memory)
- support for images with delayed import, tls, seh, etc.

### Documentation

#### Library Flags

Flags can be combined 

`LIBRARYEX_NONE`: Map module from disk into memory and execute entrypoint.

`LIBRARYEX_BYPASS_LOAD_CALLBACK`: Map module from disk into private memory (unbacked) which bypasses image load callbacks (`PsSetLoadImageNotifyRoutine`)

`LIBRARYEX_NO_ENTRY`: Do not execute the entrypoint of the module.

`LIBRARYEX_BUFFER`: Map the module from memory instead from disk.

#### Function: `LdrLibrary` 
Easy to use function to load a library into memory. The first param, based on what flags has been specified, can be either a wide string module name to load or memory address where the PE is located at.

```c
/*!
 * @brief
 *  load library into memory
 *
 * @param Buffer
 *  buffer context to load library
 *  either a wide string or a buffer pointer 
 *  the to PE file to map (LIBRARYEX_BUFFER)
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
);
```

This example shows how to load a module from disk (from the System32 path): 
```c
PVOID Module = { 0 };
ULONG Flags  = { 0 };

//
// mapping flags to be used by the library
//
Flags = LIBRARYEX_NONE; 

//
// map file into memory
//
if ( ! NT_SUCCESS( Status = LdrLibrary( L"advapi32.dll", &Module, Flags ) ) ) {
    printf( "[-] LdrLibraryEx Failed: %p\n", Status );
    return; 
}

printf( "[*] Module @ %p\n", Module );
```

This examples shows how to load a module from a memory buffer: 
```c
PVOID Module = { 0 };
ULONG Flags  = { 0 };

//
// mapping flags to be used by the library
//
Flags = LIBRARYEX_NONE  | 
        LIBRARYEX_BUFFER; 

//
// read file on disk into memory
//
if ( ! ( Image = ReadFileBuffer( L"C:\\Windows\\System32\\advapi32.dll", NULL ) ) ) {
    puts( "[-] ReadFileBuffer Failed" );
    return;
}

//
// map file into memory
//
if ( ! NT_SUCCESS( Status = LdrLibrary( Image, &Module, Flags ) ) ) {
    printf( "[-] LdrLibraryEx Failed: %p\n", Status );
    return;
}

printf( "[*] Module @ %p\n", Module );
```

It is also possible to load modules based on their api set (win10+ support only):
```c
//
// map file into memory
//
if ( ! NT_SUCCESS( Status = LdrLibrary( L"api-ms-win-base-util-l1-1-0.dll", &Module, Flags ) ) ) {
    printf( "[-] LdrLibraryEx Failed: %p\n", Status );
    return;
}

printf( "[*] Module @ %p\n",  );
```

#### Function: `LdrLibraryEx`
LdrLibraryEx allows to hook certain functions to modify the behaviour of how a library should be mapped into memory. 
```c
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
    printf( "[-] LdrLibraryCtx Failed: %d\n", Status );
    goto END;
}

//
// hook function
//
Ctx.LdrLoadDll = C_PTR( HookLdrLoadDll );

//
// map file into memory
//
if ( ! NT_SUCCESS( Status = LdrLibraryEx( &Ctx, L"cryptsp.dll", &Module, Flags ) ) ) {
    printf( "[-] LdrLibraryEx Failed: %p\n", Status );
    return; 
}
```

### Note
This codebase is written and optimized for x86_64-mingw and it most likely not going to work and or compile under Visual Studio.

## Credits
Huge credit goes out to following resources and projects: 
- [DarkLoadLibrary](https://github.com/bats3c/DarkLoadLibrary)
- [MDSec: Bypassing Image loader kernel callbacks](https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/)
- [ReactOS LdrLoadDll](https://doxygen.reactos.org/d7/d55/ldrapi_8c.html#a7671bda932dbb5096570f431ff83474c)
- [Vergilius Project](https://www.vergiliusproject.com/)

this project shouldn't be used in a real world env or operation. I mainly wrote this to understand and learn more about how windows loader works. I wrote it as a library because I wanted to use this for other type of public and private projects. I achieved my goal. Cya.  
