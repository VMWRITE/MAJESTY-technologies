#pragma once
#include "NtApiDef.h"
#include "ApiWrapper.hpp"


#define Log(x,...)  Util::Print(xorstr_(x), __VA_ARGS__)




namespace Util
{

	 


	__forceinline  ULONG KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type)
	{


		UNICODE_STRING u_title = ApiWrapper::InitUnicodeString(title);
		UNICODE_STRING u_text = ApiWrapper::InitUnicodeString(text);

		ULONG_PTR args[] = { (ULONG_PTR)&u_text, (ULONG_PTR)&u_title, type };
		ULONG response = 0;



		ExRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, args, 1, &response);


		ApiWrapper::FreeUnicodeString(u_title);
		ApiWrapper::FreeUnicodeString(u_text);

		return response;
	}


	__forceinline  DWORD64	GetProcAddress(const uintptr_t imageBase, const char* exportName) {

		if (!imageBase)
			return 0;

		if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
			return 0;

		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
		const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
		if (!exportDirectory)
			0;

		const auto exportedFunctions = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfFunctions);
		const auto exportedNames = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfNames);
		const auto exportedNameOrdinals = reinterpret_cast<UINT16*>(imageBase + exportDirectory->AddressOfNameOrdinals);

		for (size_t i{}; i < exportDirectory->NumberOfNames; ++i) {
			const auto functionName = reinterpret_cast<const char*>(imageBase + exportedNames[i]);
			if (NoCRT::string::stricmp(exportName, functionName) == 0) {
				return imageBase + exportedFunctions[exportedNameOrdinals[i]];

			}
		}

		return 0;
	}

	__forceinline DWORD64 GetKernelBasebyDisk(const wchar_t* name)
	{


		PDRIVER_OBJECT DiskDriver = NULL;

		UNICODE_STRING  DriverName = ApiWrapper::InitUnicodeString(xorstr_(L"\\Driver\\disk"));



		auto status = ObReferenceObjectByName(
			&DriverName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			0,
			*IoDriverObjectType,
			KernelMode,
			NULL,
			(PVOID*)&DiskDriver);

		ApiWrapper::FreeUnicodeString(DriverName);

		if (NT_SUCCESS(status))
		{


			PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DiskDriver->DeviceObject->DriverObject->DriverSection;
			PLDR_DATA_TABLE_ENTRY first = entry;
			while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderModuleList.Flink != first)
			{

				if (NoCRT::string::wstricmp(entry->BaseDllName.Buffer, name) == 0)
				{
					ObDereferenceObject(DiskDriver);
					return	(DWORD64)entry->DllBase;
				}
				entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderModuleList.Flink;


			}
			return 0;

		}
		else
		{
			return 0;
		}

	}

	__forceinline  ULONG Print(const char* text, ...)
	{

		va_list(args);
		va_start(args, text);


		auto myvDbgPrintExWithPrefix = (t_vDbgPrintExWithPrefix)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("vDbgPrintExWithPrefix"));
		auto result = myvDbgPrintExWithPrefix(xorstr_("[sex technology] "), 0, 0, text, args);

		va_end(args);
		return result;

	}
	 

	bool  CheckMask(const char* base, const char* pattern, const char* mask)
	{
		for (; *mask; ++base, ++pattern, ++mask)
		{
			if ('x' == *mask && *base != *pattern)
			{
				return false;
			}
		}

		return true;
	}


	PVOID FindPattern(PVOID base, int length, const char* pattern, const char* mask)
	{
		length -= static_cast<int>(NoCRT::string::strlen(mask));
		for (auto i = 0; i <= length; ++i)
		{
			const auto* data = static_cast<char*>(base);
			const auto* address = &data[i];
			if (CheckMask(address, pattern, mask))
				return PVOID(address);
		}

		return nullptr;
	}

	PVOID FindPatternImage(PVOID base, const char* secthionName, const char* pattern, const char* mask)
	{
		PVOID match = nullptr;

		auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(headers);

		for (auto i = 0; i < headers->FileHeader.NumberOfSections; ++i)
		{
			auto* section = &sections[i];
			if ('EGAP' == *(PINT)section->Name || NoCRT::mem::memcmp(section->Name, ".text", 5) == 0)
			{
				match = FindPattern(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (match)
					break;
			}
		}

		return match;
	}
}