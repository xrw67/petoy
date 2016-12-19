#ifndef _PETOY_COMMON_H_
#define _PETOY_COMMON_H_

// ≈‰÷√
#define PETOY_VERSION "0.1.0"


#include <stdio.h>
#include <stdint.h>
#include <string>

#ifdef WIN32
	#pragma warning(disable:4819)
	#pragma warning(disable:4996)
	#define snprintf _snprintf

	#if _MSC_VER < 1500 // MSVC 2008
		#define vsnprintf _vsnprintf
	#endif
#endif

namespace petoy {

enum EC {
	SUCCESS = 0,
    ERR_NO_MEM,
	ERR_FILE_OPEN,
	ERR_FILE_WRITE,
	ERR_FILE_READ,
    ERR_NOT_PE,
    ERR_NOT_EXE_OR_DLL,
    ERR_PACKED,
};

static std::string errString(EC eno)
{
	switch (eno) {
	case SUCCESS: return "Success";
	case ERR_NO_MEM: return "Alloc memory failed";
	case ERR_FILE_OPEN: return "Open file failed";
	case ERR_FILE_WRITE: return "Write file failed";
	case ERR_FILE_READ: return "Read file failed";
	case ERR_NOT_PE: return "Not a PE";
	case ERR_NOT_EXE_OR_DLL: return "Not a EXE or DLL";
	case ERR_PACKED: return "Pack file failed";
	}
	return "Unkown error!";
}

#define MAX_IO_BLOCK_SIZE (1024 * 1024)

static EC freadFixed(FILE *f, void * _buf, size_t num_bytes)
{
	char * buf = (char *)_buf;

	while (num_bytes != 0) {
		size_t block_size = num_bytes;
		if (block_size > MAX_IO_BLOCK_SIZE) block_size = MAX_IO_BLOCK_SIZE;

		size_t r = fread(buf, 1, block_size, f);
		if (r != block_size)
            return ERR_FILE_READ;

		buf       += block_size;
		num_bytes -= block_size;
	}
    return SUCCESS;
}

static EC fwriteFixed(FILE *f, const void * _buf, size_t num_bytes) 
{
	const char * buf = (const char *)_buf;

	while (num_bytes != 0) {
		size_t block_size = num_bytes;
		if (block_size > MAX_IO_BLOCK_SIZE) block_size = MAX_IO_BLOCK_SIZE;

		size_t r = fwrite(buf, 1, block_size, f);
		if (r != block_size)
            return ERR_FILE_WRITE;

		buf       += block_size;
		num_bytes -= block_size;
	}
	return SUCCESS;
}

static EC fwriteZero(FILE *f, size_t num_bytes)
{
	char c = 0;

	while (num_bytes--) {
		size_t r = fwrite(&c, 1, 1, f);
		if (r != 1)
			return ERR_FILE_WRITE;
	}
	return SUCCESS;
}

static size_t getLenOfFile(FILE *f) 
{
	fseek(f, 0, SEEK_END);
	return ftell(f);
}

} // namespace petoy

#endif // _PETOY_COMMON_H_
