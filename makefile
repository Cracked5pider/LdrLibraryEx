MAKEFLAGS += "-s"

##
## Compilers
##
CC_X64 := x86_64-w64-mingw32-gcc

##
## Compiler flags
##
CFLAGS	:=  -Os -fno-asynchronous-unwind-tables
CFLAGS 	+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	+= -falign-labels=1 -fPIC
CFLAGS	+= -Wl,-s,--no-seh,--enable-stdcall-fixup -municode
CFLAGS  += -Iinclude -masm=intel -DLIBRARYEX_DEBUG

test: clean-builds test-cryptsp.exe test-cryptsp-ex.exe test-cryptsp-buffer.exe test-rundll32.exe test-api-set.exe

test-cryptsp.exe:
	printf "[*] build test test-cryptsp.exe..."
	$(CC_X64) tests/TestCryptsp.c src/LdrLibraryEx.c -o test-cryptsp.exe $(CFLAGS)
	echo " done"

test-cryptsp-ex.exe:
	printf "[*] build test test-cryptsp-ex.exe..."
	$(CC_X64) tests/TestCryptspEx.c src/LdrLibraryEx.c -o test-cryptsp-ex.exe $(CFLAGS)
	echo " done"

test-cryptsp-buffer.exe:
	printf "[*] build test test-cryptsp-buffer.exe..."
	$(CC_X64) tests/TestCryptspMemory.c src/LdrLibraryEx.c -o test-cryptsp-buffer.exe $(CFLAGS)
	echo " done"

test-rundll32.exe:
	printf "[*] build test test-rundll32.exe..."
	$(CC_X64) tests/TestRundll32Exe.c src/LdrLibraryEx.c -o test-rundll32.exe $(CFLAGS)
	echo " done"

test-api-set.exe:
	printf "[*] build test test-api-set.exe..."
	$(CC_X64) tests/TestApiSet.c src/LdrLibraryEx.c -o test-api-set.exe $(CFLAGS)
	echo " done"

clean-builds:
	rm -rf *.exe

clean: clean-builds
	rm -rf .idea
	rm -rf cmake-build-debug
