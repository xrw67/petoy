/**
 * 壳的数据部分
 * (采用数据块的形式保存数据)
 * +--------+-------+--------+-------+--------+-------+
 * | Header | Block | Header | Block | ...    |   0   |
 * +--------+-------+--------+-------+--------+-------+
 */

#ifndef _PETOY_SHELL_H_
#define _PETOY_SHELL_H_

#include <string>
#include <memory>
#include <Windows.h>
#include "common.h"

#include <pshpack4.h>  // 4字节对齐


//
// 壳的参数
//
extern "C" DWORD ToyShellBegin;
extern "C" DWORD ToyShellEnd;
extern "C" DWORD ToyShellImportBegin;
extern "C" DWORD ToyShellImportEnd;
extern "C" DWORD ToyShellArgs;

typedef struct _TOY_SHELL_ARGS{
	DWORD ToyBlockVAddr;   // 0x00
	DWORD ToyBlockSize;    // 0x04
	DWORD OrigImageBase;   // 0x08
	DWORD OrigEntryPoint;  // 0x0c
} TOY_SHELL_ARGS, *PTOY_SHELL_ARGS;

//
// 壳的数据块头部
//

#define TOY_BLOCK_ALIGN       4     // 数据块4字节对齐
#define TOY_BLOCK_ALIGN_MASK  0x3

#define TOY_TYPE_SECTION    1       // 数据块表示一个区块
#define TOY_TYPE_IMPORT     2       // 数据块表示导入表
#define TOY_TYPE_BASERELOC  3       // 数据块表示基值重定位数据

typedef struct _TOY_BLOCK_HEADER {
	DWORD Size;
	DWORD Type;
} TOY_BLOCK_HEADER, *PTOY_BLOCK_HEADER;

//
// 导入表
// (每一块都是一个TOY_IMPORT_THUNK结构体，结尾有一个全为0的结构体)
// +---------+------------+----------+-----+---+
// | DllName | FirstThunk | Function | ... | 0 |
// +---------+------------+----------+-----+---+
//

typedef struct TOY_IMPORT_THUNK {
	DWORD Size;
	DWORD Type;
	//union {
	//	DWORD FirstThunk;  // 原来的FirstThunk的RVA
	//	DWORD Ordinal;     // 序号
	//	CHAR  DllName[1];  // Dll名
	//	CHAR  FuncName[1]; // 函数名
	//};
} TOY_IMPORT_THUNK, *PTOY_IMPORT_THUNK;


enum {
	TOY_IMPORT_TYPE_DLLNAME = 1,
	TOY_IMPORT_TYPE_FIRST_THUNK,
	TOY_IMPORT_TYPE_ORDINAL,
	TOY_IMPORT_TYPE_FUNC_NAME,
};

#define TOY_IMPORT_THUNK_DATA(x) ((char *)((DWORD)x + sizeof(*x)))
#define TOY_IMPORT_THUNK_NEXT(x) ((PTOY_IMPORT_THUNK)((DWORD)x + x->Size))

//
// 基值重定位表格式
//

typedef struct _TOY_BASE_RELOC {
	DWORD VirtualAddress;
	DWORD Type;
	DWORD Number;
	// WORD  Offset[1];
} TOY_BASE_RELOC, *PTOY_BASE_RELOC;

#define TOY_BASE_RELOC_DATA(x) ((PWORD)((DWORD)x + sizeof(*x)))

//
// 区块信息
//

typedef struct _TOY_SECTION {
	DWORD Encrypt;
	DWORD OrignalAddr;
	DWORD PackedSize;
	// BYTE Data[1]
} TOY_SECTION, *PTOY_SECTION;

#define TOY_SECTION_DATA(x) ((char *)((DWORD)x + sizeof(*x)))

#include <poppack.h>

namespace petoy {

class ToyBlock {
public:
	ToyBlock() 
		: _buf(NULL), _used(0), _bufSize(0) 
	{
	}

	ToyBlock(int type, size_t dataHeaderSize)
	{
		create(type, dataHeaderSize);
	}

	~ToyBlock()
	{
		if (_buf) {
			delete []_buf;
			_used = _bufSize = 0;
		}
	}
	
	void create(int type, size_t dataHeaderSize)
	{
		PTOY_BLOCK_HEADER blockHeader;

		if ((sizeof(TOY_BLOCK_HEADER) + dataHeaderSize) > DefaultBlockSize)
			_bufSize = roundupPowOfTwo(sizeof(*blockHeader) + dataHeaderSize);
		else
			_bufSize = DefaultBlockSize;

		_buf = new char[_bufSize];
		_used = sizeof(*blockHeader) + dataHeaderSize;
		memset(_buf, 0, _bufSize);

		blockHeader = (PTOY_BLOCK_HEADER)_buf;
		blockHeader->Type = type;
	}
	
	PTOY_BLOCK_HEADER blockHeader(void)
	{ 
		return (PTOY_BLOCK_HEADER)_buf;
	}
	
	void *dataHeader(void)
	{ 
		return (void *)(_buf + sizeof(TOY_BLOCK_HEADER));
	}
	
	void finish(void)
	{
		size_t fill;
		PTOY_BLOCK_HEADER hdr = (PTOY_BLOCK_HEADER)_buf;
		
		// 对齐4字节大小
		fill = TOY_BLOCK_ALIGN - (_used & TOY_BLOCK_ALIGN_MASK);
		while (fill-- > 0)
			pushByte(0);

		hdr->Size = _used;
	}

	DWORD size(void) const
	{ 
		return _used;
	}
	
	DWORD type(void) const
	{
		PTOY_BLOCK_HEADER hdr = (PTOY_BLOCK_HEADER)_buf;
		return hdr->Type;
	}
	
	char *get(void) const
	{ 
		return _buf;
	}

	char *pushByte(BYTE b)
	{ 
		return push(&b, sizeof(BYTE));
	}
	
	char *pushWord(WORD w)
	{ 
		return push(&w, sizeof(WORD));
	}
	
	char *pushDword(DWORD dw)
	{ 
		return push(&dw, sizeof(DWORD));
	}
	
	char *pushString(const char *s)
	{ 
		return push(s, strlen(s) + 1);
	}
	
	char *pushString(const std::string &s)
	{ 
		return push(s.c_str(), s.length() + 1);
	}
	
	char *push(const void *buf, size_t len)
	{
		size_t newUsed = _used + len;

		if (newUsed > _bufSize) {
			_bufSize = roundupPowOfTwo(newUsed);
			char *n = new char[_bufSize];
			memset(n, 0, _bufSize);
			memcpy(n, _buf, _used);
			delete []_buf;
			_buf = n;
		}

		memcpy(&_buf[_used], buf, len);
		_used += len;
		return &_buf[_used - len];
	}

private:
	static const size_t DefaultBlockSize = 0x1000;

	size_t roundupPowOfTwo(size_t size)
	{
		int n = 0;
		while (0 != size) {
			size >>= 1;
			++n;
		}
		return 1 << (n + 1);
	}

	char *_buf;
	size_t _bufSize;
	size_t _used;
};

typedef std::shared_ptr<ToyBlock> ToyBlockPtr;

} // namespace petoy

#endif // _PETOY_SHELL_H_
