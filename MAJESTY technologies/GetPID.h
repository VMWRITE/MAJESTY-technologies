#pragma once
#include "Util.hpp"


//	https://www.unknowncheats.me/forum/c-and-c-/467342-kernel-getting-pid-xp-vista-7-8-8-1-10-11-a.html
namespace PIDHelp
{
 

	__forceinline NTSTATUS  GetPEprocessByProcName(IN const CHAR* szProcessName, OUT PEPROCESS* pProcessInfo)
	{

		UINT OffsetUniqueProcessId = 0x0;
		UINT OffsetActiveProcessLinks = 0x0;
		UINT OffsetImageFileName = 0x0;
		UINT OffsetActiveThreads = 0x0;

		auto myPsInitialSystemProcess = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsInitialSystemProcess"));


		PEPROCESS SystemProcess = (PEPROCESS)*myPsInitialSystemProcess;

		for (int i = 0; i < 0xFFF; i++) // 0xFFF larger than the size of full struct
		{
			if (!OffsetUniqueProcessId && !OffsetActiveProcessLinks)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) == 4 && // 4 always, pid of system process
					*(UINT64*)((UINT64)SystemProcess + i + 0x8) > 0xFFFF000000000000)  // > 0xFFFF000000000000 always
				{
					OffsetUniqueProcessId = i;
					OffsetActiveProcessLinks = i + 0x8;
				}
			}
			if (!OffsetImageFileName && !OffsetActiveThreads)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) > 0x0000400000000000 && *(UINT64*)((UINT64)SystemProcess + i) < 0x0000800000000000 && // 0x00006D6574737953 always, but better to make range
					*(UINT64*)((UINT64)SystemProcess + i + 0x48) > 0 && *(UINT64*)((UINT64)SystemProcess + i + 0x48) < 0xFFF) // 80 ~ 300 in general
				{
					OffsetImageFileName = i;
					OffsetActiveThreads = i + 0x48;
				}
			}

			if (OffsetUniqueProcessId && OffsetActiveProcessLinks && OffsetImageFileName && OffsetActiveThreads)
			{



				PEPROCESS CurrentProcess = SystemProcess;

				do
				{
					if (NoCRT::string::strstr((CHAR*)((UINT64)CurrentProcess + OffsetImageFileName), szProcessName))
					{
						if (*(UINT*)((UINT64)CurrentProcess + OffsetActiveThreads))
						{
							*pProcessInfo = CurrentProcess;
							return STATUS_SUCCESS;
						}
					}

					PLIST_ENTRY List = (PLIST_ENTRY)((UINT64)(CurrentProcess)+OffsetActiveProcessLinks);
					CurrentProcess = (PEPROCESS)((UINT64)List->Flink - OffsetActiveProcessLinks);

				} while (CurrentProcess != SystemProcess);

				return STATUS_NOT_FOUND;



			}
		}

		return STATUS_NOT_FOUND;
	}



	__forceinline  HANDLE GetID(IN const CHAR* szProcessName)
	{



		UINT OffsetUniqueProcessId = 0x0;
		UINT OffsetActiveProcessLinks = 0x0;
		UINT OffsetImageFileName = 0x0;
		UINT OffsetActiveThreads = 0x0;


		auto myPsInitialSystemProcess = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsInitialSystemProcess"));



		PEPROCESS SystemProcess = (PEPROCESS)*myPsInitialSystemProcess;

		PEPROCESS CurrentProcess = SystemProcess;


		for (int i = 0; i < 0xFFF; i++) // 0xFFF larger than the size of full struct
		{



			if (!OffsetUniqueProcessId && !OffsetActiveProcessLinks)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) == 4 && // 4 always, pid of system process
					*(UINT64*)((UINT64)SystemProcess + i + 0x8) > 0xFFFF000000000000)  // > 0xFFFF000000000000 always
				{
					OffsetUniqueProcessId = i;
					OffsetActiveProcessLinks = i + 0x8;
				}
			}




			if (!OffsetImageFileName && !OffsetActiveThreads)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) > 0x0000400000000000 && *(UINT64*)((UINT64)SystemProcess + i) < 0x0000800000000000 && // 0x00006D6574737953 always, but better to make range
					*(UINT64*)((UINT64)SystemProcess + i + 0x48) > 0 && *(UINT64*)((UINT64)SystemProcess + i + 0x48) < 256) // 50 ~ 70 in general
				{
					OffsetImageFileName = i;
					OffsetActiveThreads = i + 0x48;
				}
			}

			if (OffsetUniqueProcessId && OffsetActiveProcessLinks && OffsetImageFileName && OffsetActiveThreads)

			{

				do
				{
					if (NoCRT::string::strstr((CHAR*)((UINT64)CurrentProcess + OffsetImageFileName), szProcessName))
					{
						if (*(ULONG*)((UINT64)CurrentProcess + OffsetActiveThreads))
						{


							return *(HANDLE*)((UINT64)CurrentProcess + OffsetUniqueProcessId);
						}
					}

					PLIST_ENTRY List = (PLIST_ENTRY)((UINT64)(CurrentProcess)+OffsetActiveProcessLinks);
					CurrentProcess = (PEPROCESS)((UINT64)List->Flink - OffsetActiveProcessLinks);

				} while (CurrentProcess != SystemProcess);

				return 0;


			}
		}

		return 0;
	}
	 
	__forceinline  NTSTATUS GetEProcessByProcId(HANDLE procId, OUT PEPROCESS* pProcessInfo)
	{



		UINT OffsetUniqueProcessId = 0x0;
		UINT OffsetActiveProcessLinks = 0x0;
		UINT OffsetImageFileName = 0x0;
		UINT OffsetActiveThreads = 0x0;


		auto myPsInitialSystemProcess = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsInitialSystemProcess"));



		PEPROCESS SystemProcess = (PEPROCESS)*myPsInitialSystemProcess;

		PEPROCESS CurrentProcess = SystemProcess;


		for (int i = 0; i < 0xFFF; i++) // 0xFFF larger than the size of full struct
		{



			if (!OffsetUniqueProcessId && !OffsetActiveProcessLinks)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) == 4 && // 4 always, pid of system process
					*(UINT64*)((UINT64)SystemProcess + i + 0x8) > 0xFFFF000000000000)  // > 0xFFFF000000000000 always
				{
					OffsetUniqueProcessId = i;
					OffsetActiveProcessLinks = i + 0x8;
				}
			}




			if (!OffsetImageFileName && !OffsetActiveThreads)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) > 0x0000400000000000 && *(UINT64*)((UINT64)SystemProcess + i) < 0x0000800000000000 && // 0x00006D6574737953 always, but better to make range
					*(UINT64*)((UINT64)SystemProcess + i + 0x48) > 0 && *(UINT64*)((UINT64)SystemProcess + i + 0x48) < 256) // 50 ~ 70 in general
				{
					OffsetImageFileName = i;
					OffsetActiveThreads = i + 0x48;
				}
			}

			if (OffsetUniqueProcessId && OffsetActiveProcessLinks && OffsetImageFileName && OffsetActiveThreads)

			{
				
				do
				{
					if (*(HANDLE*)((UINT64)CurrentProcess + OffsetUniqueProcessId) == procId)
					{
						if (*(UINT*)((UINT64)CurrentProcess + OffsetActiveThreads))
						{ 
							*pProcessInfo = CurrentProcess;
							return STATUS_SUCCESS;
						}
					}

					PLIST_ENTRY List = (PLIST_ENTRY)((UINT64)(CurrentProcess)+OffsetActiveProcessLinks);
					CurrentProcess = (PEPROCESS)((UINT64)List->Flink - OffsetActiveProcessLinks);

				} while (CurrentProcess != SystemProcess);

				return STATUS_NOT_FOUND;
				 

			}
		}

		return STATUS_NOT_FOUND;
	}
	 

	__forceinline  PEPROCESS GetEProcessByProcIdEx(HANDLE procId)
	{



		UINT OffsetUniqueProcessId = 0x0;
		UINT OffsetActiveProcessLinks = 0x0;
		UINT OffsetImageFileName = 0x0;
		UINT OffsetActiveThreads = 0x0;


		auto myPsInitialSystemProcess = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsInitialSystemProcess"));



		PEPROCESS SystemProcess = (PEPROCESS)*myPsInitialSystemProcess;

		PEPROCESS CurrentProcess = SystemProcess;


		for (int i = 0; i < 0xFFF; i++) // 0xFFF larger than the size of full struct
		{



			if (!OffsetUniqueProcessId && !OffsetActiveProcessLinks)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) == 4 && // 4 always, pid of system process
					*(UINT64*)((UINT64)SystemProcess + i + 0x8) > 0xFFFF000000000000)  // > 0xFFFF000000000000 always
				{
					OffsetUniqueProcessId = i;
					OffsetActiveProcessLinks = i + 0x8;
				}
			}




			if (!OffsetImageFileName && !OffsetActiveThreads)
			{
				if (*(UINT64*)((UINT64)SystemProcess + i) > 0x0000400000000000 && *(UINT64*)((UINT64)SystemProcess + i) < 0x0000800000000000 && // 0x00006D6574737953 always, but better to make range
					*(UINT64*)((UINT64)SystemProcess + i + 0x48) > 0 && *(UINT64*)((UINT64)SystemProcess + i + 0x48) < 256) // 50 ~ 70 in general
				{
					OffsetImageFileName = i;
					OffsetActiveThreads = i + 0x48;
				}
			}

			if (OffsetUniqueProcessId && OffsetActiveProcessLinks && OffsetImageFileName && OffsetActiveThreads)

			{

				do
				{
					if (*(HANDLE*)((UINT64)CurrentProcess + OffsetUniqueProcessId) == procId)
					{
						if (*(UINT*)((UINT64)CurrentProcess + OffsetActiveThreads))
						{
							return  CurrentProcess;
						 
						}
					}

					PLIST_ENTRY List = (PLIST_ENTRY)((UINT64)(CurrentProcess)+OffsetActiveProcessLinks);
					CurrentProcess = (PEPROCESS)((UINT64)List->Flink - OffsetActiveProcessLinks);

				} while (CurrentProcess != SystemProcess);

				return 0;


			}
		}

		return 0;
	}

}