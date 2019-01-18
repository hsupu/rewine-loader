CC=gcc

DUMMY=

OBJ_COMMON_DIR= ../../common
OBJ_COMMON= \
	$(OBJ_COMMON_DIR)/internal/linker/mapping.o \
	$(OBJ_COMMON_DIR)/types/bstr.o \
	$(OBJ_COMMON_DIR)/types/linkedlist.o \
	$(OBJ_COMMON_DIR)/types/wstr.o \
	$(OBJ_COMMON_DIR)/misc/fs.o \
	$(OBJ_COMMON_DIR)/misc/raii.o \
	$(DUMMY)

OBJ_DLL_DIR= ../../dlls
OBJ_DLL= \
	$(OBJ_DLL_DIR)/ntdll.dll/ldr.o \
	$(OBJ_DLL_DIR)/ntdll.dll/rtl.o \
	$(DUMMY)

OBJ_LINKER= \
	pe-stub/pe-stub-i386.o \
	pe-stub/pe-stub-x86_64.o \
	pe-stub/pe-stub.o \
	pe-loader.o \
	$(DUMMY)

OBJ_TESTS= \
	tests/pe-loader-test.o \
	$(DUMMY)

FINAL=a.out

CFLAGS= -std=c11 -g -O0 -I. -I../../include -D_WIN64 -D_POSIX_C_SOURCE=20190115


.PHONE: all
all: a.out


.PHONY: clean
clean:
	rm -rf *.o


$(OBJ_COMMON) $(OBJ_DLL) $(OBJ_LINKER): %.o : %.c
	$(CC) -o $@ -c $(CFLAGS) $<

$(OBJ_TESTS) : %.o : %.c
	$(CC) -o $@ -c $(CFLAGS) $<


a.out: $(OBJ_COMMON) $(OBJ_DLL) $(OBJ_LINKER) $(OBJ_TESTS)
	$(CC) -o a.out $(CFLAGS) \
		$(OBJ_COMMON) $(OBJ_DLL) $(OBJ_LINKER) $(OBJ_TESTS) \
		$(DUMMY)
