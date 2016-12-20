#include "packer.h"
#include "aPLib\lib\coff\aplib.h"

namespace petoy {

Packer::Packer()
	: _imageBase(NULL), _imageSize(0), _extendBase(NULL), _extendSize(0)
	, _dosHeader(NULL), _ntHeaders(NULL), _secHeaders(NULL)
{
}

Packer::~Packer()
{
}

EC Packer::load(const std::string &filename)
{
    EC err = SUCCESS;
    int i;
    size_t fileSize;
    size_t extendOffset;
    FILE *f;
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_NT_HEADERS ntHdr;
    PIMAGE_SECTION_HEADER secPos;
    size_t fileAlign;
    size_t secAlign;

    f = fopen(filename.c_str(), "rb");
    if (!f)
        return ERR_FILE_OPEN;

    fileSize = getLenOfFile(f);

    fseek(f, 0, SEEK_SET);
    err = freadFixed(f, &dosHdr, sizeof(dosHdr));
    if (SUCCESS != err)
        goto out;

    if (IMAGE_DOS_SIGNATURE != dosHdr.e_magic) { // DOS magic
        err = ERR_NOT_PE;
        goto out;
    }

    fseek(f, dosHdr.e_lfanew, SEEK_SET);
    err = freadFixed(f, &ntHdr, sizeof(ntHdr));
    if (SUCCESS != err)
        goto out;

    if (IMAGE_NT_SIGNATURE != ntHdr.Signature) { // PE signature
        err = ERR_NOT_PE;
        goto out;
    }

    //
    // Load image
    //

    fileAlign = ntHdr.OptionalHeader.FileAlignment;
    secAlign = ntHdr.OptionalHeader.SectionAlignment;
    _imageSize = alignSize(ntHdr.OptionalHeader.SizeOfImage, secAlign);
    _imageBase = new char[_imageSize];
    if (!_imageBase) {
        err = ERR_NO_MEM;
        goto out;
    }
    memset(_imageBase, 0, _imageSize);

    fseek(f, 0, SEEK_SET);
    err = freadFixed(f, _imageBase, ntHdr.OptionalHeader.SizeOfHeaders);

    _dosHeader = (PIMAGE_DOS_HEADER)_imageBase;
    _ntHeaders = (PIMAGE_NT_HEADERS)(_imageBase + dosHdr.e_lfanew);
    _secHeaders = (PIMAGE_SECTION_HEADER)((char *)_ntHeaders + 
        sizeof(ntHdr.Signature) + sizeof(ntHdr.FileHeader) + ntHdr.FileHeader.SizeOfOptionalHeader);

    // 各区块数据
    for (i = 0, secPos = _secHeaders; i < ntHdr.FileHeader.NumberOfSections; i++, secPos++) {
        fseek(f, secPos->PointerToRawData, SEEK_SET);
        err = freadFixed(f, _imageBase + secPos->VirtualAddress, secPos->SizeOfRawData);
        if (SUCCESS != err)
            goto out;
    }
    
    secPos--; // 最后一个区块
    
    // 修正SizeOfImage可能存在的对齐问题
    _ntHeaders->OptionalHeader.SizeOfImage = secPos->VirtualAddress + secPos->Misc.VirtualSize;

    // 额外数据
    extendOffset = secPos->PointerToRawData + secPos->SizeOfRawData;
    _extendSize = fileSize - extendOffset;
    if (_extendSize > 0) {
        _extendBase = new char[_extendSize];
        if (!_extendBase) {
            err = ERR_NO_MEM;
            goto out;
        }
        memset(_extendBase, 0, _extendSize);

        fseek(f, extendOffset, SEEK_SET);
        err = freadFixed(f, _extendBase, _extendSize);
        if (SUCCESS != err)
            goto out;
    }
    
    fclose(f);
    return SUCCESS;

out:
    if (f) fclose(f);
    if (_imageSize > 0 ) {_imageSize = 0; delete []_imageBase;}
    if (_extendSize > 0) { _extendSize = 0; delete []_extendBase; }
    return err;
}

EC Packer::pack(const std::string &savename)
{
    EC err = SUCCESS;
	int i;
    FILE *f;
	PIMAGE_DATA_DIRECTORY importDir, boundDir, iatDir, baseRelocDir;
	PIMAGE_SECTION_HEADER secPos, shellHdr;
	PIMAGE_IMPORT_DESCRIPTOR shellImportHdr;
	std::vector<ToyBlock *> toyBlockList;
	bool isDll = false, isExe = false;

	int packedSecIndex = 0;

    // 可能已经被压缩
    if (1 == _ntHeaders->FileHeader.NumberOfSections ||
            _ntHeaders->OptionalHeader.AddressOfEntryPoint >= _secHeaders[1].VirtualAddress)
        return ERR_PACKED;
    
    // 不是EXE或者DLL
	if (_ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		isExe = true;
	else if (_ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		isDll = true;
	else
        return ERR_NOT_EXE_OR_DLL;

    f = fopen(savename.c_str(), "wb");
    if (!f)
        return ERR_FILE_OPEN;

	// 清除绑定输入
	boundDir = &(_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]);
	if (boundDir->VirtualAddress) {
		memset(RvaPtr(boundDir->VirtualAddress), 0, boundDir->Size);
		boundDir->VirtualAddress = boundDir->Size = 0;
	}
	printf("Remove bound import data done!\n");

	// 处理输入表
	importDir = &(_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (importDir->VirtualAddress) {
		packImport();
		memset(RvaPtr(importDir->VirtualAddress), 0, importDir->Size);
		importDir->VirtualAddress = importDir->Size = 0; // 后面会重新填充
	}
	printf("Pack import table done!\n");

	// 清除IAT
	iatDir = &(_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]);
	if (iatDir->VirtualAddress) {
		memset(RvaPtr(iatDir->VirtualAddress), 0, iatDir->Size);
		iatDir->VirtualAddress = iatDir->Size = 0;
	}
	printf("Remove IAT done!\n");

	// 处理基值重定位表
	baseRelocDir = &(_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (baseRelocDir->VirtualAddress) {
		packBaseReloc();
		memset(RvaPtr(baseRelocDir->VirtualAddress), 0, baseRelocDir->Size);
		baseRelocDir->VirtualAddress = baseRelocDir->Size = 0;
	}
	printf("Pack base relocation table done!\n");

	size_t numberOfSections, fileAlign, secAlign, sizeOfHeader;

	numberOfSections = _ntHeaders->FileHeader.NumberOfSections;
	fileAlign = _ntHeaders->OptionalHeader.FileAlignment = 0x200; // 使用最小对齐间隔
    secAlign = _ntHeaders->OptionalHeader.SectionAlignment;
    sizeOfHeader = (size_t)&_secHeaders[numberOfSections + 1] - (size_t)_imageBase; // 已考虑shell区块头
    sizeOfHeader = alignSize(sizeOfHeader, fileAlign);

    // 写文件头占位符, 后面修正文件头后，再重写一遍
    err = fwriteZero(f, sizeOfHeader);
    if (SUCCESS != err)
        goto out;

	// 处理区块
	PTOY_SECTION toySection;

	_secHeaders[0].PointerToRawData = sizeOfHeader; // 第一个区块的文件偏移

    for (i = 0, secPos = _secHeaders; i < _ntHeaders->FileHeader.NumberOfSections; i++, secPos++) {
		size_t sizeOfRawData = minSectionSize(RvaPtr(secPos->VirtualAddress), secPos->SizeOfRawData);
		
		if (sizeOfRawData == 0) {
			secPos->SizeOfRawData = 0;
		} else {
			secPos->SizeOfRawData = alignSize(sizeOfRawData, fileAlign);

			if (canSectionEncode((const char *)secPos->Name)) {
				ToyBlockPtr toyBlock(new ToyBlock(TOY_TYPE_SECTION, sizeof(*toySection)));
				char *data = (char *)RvaPtr(secPos->VirtualAddress);
				size_t dataLen = minSectionSize(data, secPos->SizeOfRawData);
				size_t need = encode(NULL, data, dataLen);

				char *encData = new char[need];
				encode(encData, data, dataLen);
				toyBlock->push(encData, need);
				delete[] encData;

				toySection = (PTOY_SECTION)toyBlock->dataHeader();
				toySection->Encrypt = 1;
				toySection->OrignalAddr = secPos->VirtualAddress;
				toySection->PackedSize = need;

				toyBlock->finish();
				_toyBlockList.push_back(toyBlock);

				secPos->SizeOfRawData = 0;
			} else {
				err = fwriteFixed(f, RvaPtr(secPos->VirtualAddress), sizeOfRawData);
				if (SUCCESS != err)
					goto out;
				err = fwriteZero(f, secPos->SizeOfRawData - sizeOfRawData);
				if (SUCCESS != err)
					goto out;
			}
		}

		secPos->Misc.VirtualSize = alignSize(secPos->Misc.VirtualSize, secAlign);
		secPos->Characteristics |= IMAGE_SCN_MEM_WRITE;
		
		printf("Pack section %s done!\n", (const char *)secPos->Name);

		// 修正下一个区块文件偏移
		if (i != (numberOfSections - 1))
			secPos[1].PointerToRawData = secPos->PointerToRawData + secPos->SizeOfRawData;
    }

	//
	// 处理壳
	//
	PTOY_SHELL_ARGS shellArgs;
	size_t shellSize, shellCodeSize, shellDataSize = 0;
	char *shellBase, *shellDataPtr;

	// 解压后的总大小
	shellDataSize = getBlockListSize();
	shellCodeSize = (size_t)&ToyShellEnd - (size_t)&ToyShellBegin;
	shellSize = alignSize(shellCodeSize, 4) + shellDataSize;

	// 复制数据
	shellBase = new char[shellSize];
	shellDataPtr = shellBase + alignSize(shellCodeSize, 4);
	memset(shellBase, 0, shellSize);
	memcpy(shellBase, &ToyShellBegin, shellCodeSize);
	mergeBlock(shellDataPtr, &shellDataSize);
	
	shellArgs = (PTOY_SHELL_ARGS)(shellBase + (size_t)&ToyShellArgs - (size_t)&ToyShellBegin);

	// 压缩数据
	char *packStart =  shellBase + shellArgs->ToyPackVAddr;
	size_t packBufSize = shellSize - shellArgs->ToyPackVAddr;
	char *workmem = new char[aP_workmem_size(packBufSize)];
	char *compressed = new char[aP_max_packed_size(packBufSize)];
	size_t outlength = aP_pack(packStart, compressed, packBufSize, workmem, NULL, NULL);
	if (outlength == APLIB_ERROR)
		goto out;

	memcpy(packStart, compressed, outlength);
	size_t shellRawSize = (size_t)packStart - (size_t)shellBase + outlength;

	shellArgs->ToyPackSize = outlength;

	// 修正壳的数据
	shellArgs->OrigImageBase = _ntHeaders->OptionalHeader.ImageBase;
	shellArgs->OrigEntryPoint = _ntHeaders->OptionalHeader.AddressOfEntryPoint;
	
	secPos = &_secHeaders[numberOfSections - 1];
	shellHdr = secPos + 1;
	_ntHeaders->FileHeader.NumberOfSections++;

	DWORD newEntryPoint = secPos->VirtualAddress + secPos->Misc.VirtualSize; // 新的入口点
	_ntHeaders->OptionalHeader.AddressOfEntryPoint = newEntryPoint;

	shellHdr->Misc.VirtualSize = alignSize(shellSize, secAlign);
	strcpy((char *)shellHdr->Name, ".petoy");
	shellHdr->NumberOfLinenumbers = 0;
	shellHdr->NumberOfRelocations = 0;
	shellHdr->PointerToLinenumbers = 0;
	shellHdr->PointerToRawData = secPos->PointerToRawData + secPos->SizeOfRawData;
	shellHdr->PointerToRelocations = 0;
	shellHdr->SizeOfRawData = alignSize(shellRawSize, fileAlign);
	shellHdr->VirtualAddress = newEntryPoint;
	shellHdr->Characteristics = 0xE0000040; // RWX + contains init data

	// 修正Shell数据块RVA
	shellArgs->ToyBlockVAddr = shellHdr->VirtualAddress + alignSize(shellCodeSize, 4);
	shellArgs->ToyBlockSize = shellDataSize;

	// 修正Shell导入表
	importDir->VirtualAddress = shellHdr->VirtualAddress + (DWORD)&ToyShellImportBegin - (DWORD)&ToyShellBegin;
	importDir->Size = (DWORD)&ToyShellImportEnd - (DWORD)&ToyShellImportBegin;

	shellImportHdr = (PIMAGE_IMPORT_DESCRIPTOR)(shellBase + (DWORD)&ToyShellImportBegin - (DWORD)&ToyShellBegin);
	for (i = 0; shellImportHdr[i].FirstThunk != 0; i++) {
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((char *)&(shellImportHdr[i]) + shellImportHdr[i].FirstThunk);

		shellImportHdr[i].OriginalFirstThunk += importDir->VirtualAddress;
		shellImportHdr[i].Name += importDir->VirtualAddress;
		shellImportHdr[i].FirstThunk += importDir->VirtualAddress;

		for (int j = 0; firstThunk[j].u1.Ordinal != 0; j++) {
			firstThunk[j].u1.Ordinal += importDir->VirtualAddress;
		}
	}

	printf("Add shellcode done!\n");

	err = fwriteFixed(f, shellBase, shellRawSize);
	if (SUCCESS != err)
		goto out;
	err = fwriteZero(f, shellHdr->SizeOfRawData - shellRawSize);
	if (SUCCESS != err)
		goto out;

	// 写文件头
	_ntHeaders->OptionalHeader.SizeOfHeaders = sizeOfHeader;
	_ntHeaders->OptionalHeader.SizeOfImage = shellHdr->VirtualAddress + shellHdr->Misc.VirtualSize;

	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
	_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;

	// 额外数据
	if (_extendSize > 0) {
		err = fwriteFixed(f, _extendBase, _extendSize);
		if (SUCCESS != err)
			goto out;
		printf("Add extend data done!\n");
	}

	fseek(f, 0, SEEK_SET);
	err = fwriteFixed(f, _imageBase, sizeOfHeader);
out:
	if (shellBase) delete []shellBase;
    if (f) fclose(f);
    return err;
}

EC Packer::unpack(const std::string &savename)
{

	return SUCCESS;
}

bool Packer::canSectionEncode(const std::string &name)
{
	static const char *secNames[] = {
		".text", ".data", ".rdata", "CODE", "DATA", ".reloc", NULL, 
	};

	for (int i = 0; secNames[i] != NULL; i++) {
		if (0 == name.compare(secNames[i]))
			return true;
	}
	return false;
}

size_t Packer::encode(char *dst, const char *src, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (dst)
			dst[i] = src[i] ^ ((char)i & 0xff);
	}
	return len;
}

size_t Packer::decode(char *dst, const char *src, size_t len)
{
	return this->encode(dst, src, len);
}

void Packer::packImport(void)
{
	char *dllName;
	PIMAGE_DATA_DIRECTORY dataDir;
	PIMAGE_IMPORT_DESCRIPTOR desc;
	PIMAGE_THUNK_DATA32 origThunk;
	
	dataDir = &(_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (dataDir->VirtualAddress == 0)
		return;

	desc = (PIMAGE_IMPORT_DESCRIPTOR)RvaPtr(dataDir->VirtualAddress);
	while (desc->Name != 0) {
		TOY_IMPORT_THUNK toyThunk;
		ToyBlockPtr toyBlock(new ToyBlock(TOY_TYPE_IMPORT, 0));

		// DllName
		dllName = (char *)RvaPtr(desc->Name);
		toyThunk.Type = TOY_IMPORT_TYPE_DLLNAME;
		toyThunk.Size = sizeof(toyThunk) + strlen(dllName) + 1;
		toyBlock->push(&toyThunk, sizeof(toyThunk));
		toyBlock->pushString(dllName);

		// FirstThunk
		toyThunk.Type = TOY_IMPORT_TYPE_FIRST_THUNK;
		toyThunk.Size = sizeof(toyThunk) + sizeof(DWORD);
		toyBlock->push(&toyThunk, sizeof(toyThunk));
		toyBlock->pushDword(desc->FirstThunk);

		// Function
		if (desc->OriginalFirstThunk)
			origThunk = (PIMAGE_THUNK_DATA32)RvaPtr(desc->OriginalFirstThunk);
		else
			origThunk = (PIMAGE_THUNK_DATA32)RvaPtr(desc->FirstThunk);

		while (origThunk->u1.Ordinal) {
			if (IMAGE_SNAP_BY_ORDINAL32(origThunk->u1.Ordinal)) {
				toyThunk.Type = TOY_IMPORT_TYPE_ORDINAL;
				toyThunk.Size = sizeof(toyThunk) + sizeof(DWORD);
				toyBlock->push(&toyThunk, sizeof(toyThunk));
				toyBlock->pushDword(IMAGE_ORDINAL32(origThunk->u1.Ordinal));
			} else {
				PIMAGE_IMPORT_BY_NAME impName;
				impName = (PIMAGE_IMPORT_BY_NAME)RvaPtr(origThunk->u1.AddressOfData);

				toyThunk.Type = TOY_IMPORT_TYPE_FUNC_NAME;
				toyThunk.Size = sizeof(toyThunk) + strlen((char *)impName->Name) + 1;
				toyBlock->push(&toyThunk, sizeof(toyThunk));
				toyBlock->pushString((char *)impName->Name);
			}
			origThunk++;
		}

		toyThunk.Type = toyThunk.Size = 0;
		toyBlock->push(&toyThunk, sizeof(toyThunk));

		toyBlock->finish();
		_toyBlockList.push_back(toyBlock);
		desc++;
	}
}

void Packer::packBaseReloc(void)
{
	PTOY_BASE_RELOC toyReloc;

	PIMAGE_DATA_DIRECTORY dataDir;
	PIMAGE_BASE_RELOCATION reloc;

	dataDir = &(_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (dataDir->VirtualAddress == 0)
		return;

	reloc = (PIMAGE_BASE_RELOCATION)RvaPtr(dataDir->VirtualAddress);
	while (reloc->VirtualAddress) {
		DWORD count = 0;
		ToyBlockPtr toyBlock(new ToyBlock(TOY_TYPE_BASERELOC, sizeof(*toyReloc)));
		PWORD offset = (PWORD)((DWORD)reloc + sizeof(*reloc));

		for (DWORD i = 0; i < (reloc->SizeOfBlock - sizeof(*reloc)) / 2; i++) {
			if (IMAGE_REL_BASED_HIGHLOW == (offset[i] >> 12)) {
				count++;
				toyBlock->pushWord(offset[i] & 0x0fff);
			}
		}

		if (count) {
			toyReloc = (PTOY_BASE_RELOC)toyBlock->dataHeader();
			
			toyReloc->VirtualAddress = reloc->VirtualAddress;
			toyReloc->Type = IMAGE_REL_BASED_HIGHLOW;
			toyReloc->Number = count;

			toyBlock->finish();
			_toyBlockList.push_back(toyBlock);
		}

		reloc = (PIMAGE_BASE_RELOCATION)((DWORD)reloc + reloc->SizeOfBlock);
	}
}

void Packer::mergeBlock(char *data, size_t *len)
{
	size_t used = 0; 
	size_t i = 0;

	// 优先合并区块信息
	while (i < _toyBlockList.size()) {
		ToyBlockPtr bk = _toyBlockList[i];

		if (bk->type() == TOY_TYPE_SECTION) {
			const size_t bkSize = bk->size();
			if (data && (used + bkSize <= *len))
				memcpy(data + used, bk->get(), bkSize);
			used += bkSize;

			_toyBlockList.erase(_toyBlockList.begin() + i);
			continue;
		}
		i++;
	}

	// 再处理其他的数据块
	for (i = 0; i <  _toyBlockList.size(); i++) {
		ToyBlockPtr bk = _toyBlockList[i];
		const size_t bkSize = bk->size();
		if (data && (used + bkSize <= *len))
			memcpy(data + used, bk->get(), bkSize);
		used += bkSize;
	}

	*len = used;
}

size_t Packer::getBlockListSize(void)
{
	size_t result = 0;

	for (size_t i = 0; i < _toyBlockList.size(); i++) {
		ToyBlockPtr bk = _toyBlockList[i];
		result += bk->size();
	}
	return result;
}

} // namespace petoy
