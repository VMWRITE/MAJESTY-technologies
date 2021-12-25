#pragma once

#include "GetPID.h"
#include "Offset.hpp"

namespace AntiDebug
{

	namespace AntiUserModeAntiDebug
	{
		//Just check DebugPort in PEPROCESS
		__forceinline	bool PsIsProcessBeingDebugged(HANDLE procId)
		{


			uint64_t IsdebugPort = 0;
			if (procId)
			{
				PEPROCESS proc;



				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{

					IsdebugPort = *(uint32_t*)((uint64_t)proc + Offset::debugOffset.DebugPort);



				}
			}
			return IsdebugPort;

		}







		//Just check NoDebugInherit  in PEPROCESS
		__forceinline	bool IsProcessDebugFlag(HANDLE procId)
		{
			/*
			NoDebugInherit safe  if  debugger detaches?
			*/


			processFlag2 IsDebugFlag{ 0 };
			if (procId)
			{
				PEPROCESS proc;


				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{
					IsDebugFlag = (*(processFlag2*)((uint64_t)proc + Offset::debugOffset.NoDebugInherit));


				}
			}
			return IsDebugFlag.NoDebugInherit;

		}


		  
		//Brute force find thread and check procId by thread
		__forceinline bool  HideManualThread(HANDLE procId)
		{

			bool IsSetHide = false;

			PETHREAD Thread;



			auto PsLookupThreadByThreadId = (t_PsLookupThreadByThreadId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsLookupThreadByThreadId"));

			 
			for (size_t i = 0; i < 35000; i++)
			{


				if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)i, &Thread)))
				{

					auto proc = *(PEPROCESS*)((uint64_t)Thread + Offset::debugOffset.Process);

					if (proc)
					{
						auto procIdProcess = *(HANDLE*)((uint64_t)proc + PIDHelp::OffsetHelp::OffsetUniqueProcessId);

						if (procId == procIdProcess)
						{
							if ((*(uint32_t*)((uint64_t)Thread + Offset::debugOffset.HideFromDebugger) & 0x4) == 0)
							{
								*(uint32_t*)((uint64_t)Thread + Offset::debugOffset.HideFromDebugger) ^= 4;
								IsSetHide =  true;


							}
						}
					}

				}

			}

			return IsSetHide;

		}


		__forceinline	bool IsUnderExplorer(HANDLE procId)
		{



			bool underExplorer = false;

			auto procIDExploler = PIDHelp::GetID(xorstr_("explorer.exe"));

			if (procId && procIDExploler)
			{
				PEPROCESS proc;

				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{
					auto uniqIdProc = *(uint64_t*)((uint64_t)proc + Offset::debugOffset.InheritedFromUniqueProcessId);


					underExplorer = (uint64_t)procIDExploler != uniqIdProc;



				}
			}
			return underExplorer;

		}




		__forceinline bool IsInstrCallbacks(HANDLE procId)
		{
			uint64_t IsInstEnable = 0;
			if (procId)
			{
				PEPROCESS proc;


				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{
					IsInstEnable = *(uint64_t*)((uint64_t)proc + Offset::debugOffset.InstrumentationCallback);


				}
			}
			return IsInstEnable != 0;
		}

	}
	namespace AntiKernelDebug
	{


		//Just call DisableKernelDebug like mhyprot(AC genshin impact) https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
		__forceinline	bool DisableKernelDebug()
		{

			auto KdDisableDebugger = (t_KdDisableDebugger)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("KdDisableDebugger"));
			auto status = KdDisableDebugger();
			return	MurmurHash2A(status,7,7) != MurmurHash2A( STATUS_DEBUGGER_INACTIVE,7,7);

			// https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html

		}

		//Call ZwSystemDebugControl with SysDbgBreakPoint
		__forceinline bool DebugTrigger()
		{

			//	https://pastebin.com/6kbt1Vka



			auto ZwSystemDebugControl = (t_ZwSystemDebugControl)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("ZwSystemDebugControl"));
			auto status = ZwSystemDebugControl(
				SysDbgBreakPoint,
				0,
				0,
				0,
				0,
				0
			);

			return MurmurHash2A(status,10,10) != MurmurHash2A(STATUS_DEBUGGER_INACTIVE,10,10);
		}

		//Call KdChangeOption like Vanguard  -> https://www.unknowncheats.me/forum/2798056-post2.html
		__forceinline	bool IsChangeOpthion()
		{

			auto KdChangeOption = (t_KdChangeOption)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("KdChangeOption"));
			auto status = KdChangeOption(KD_OPTION_SET_BLOCK_ENABLE, NULL, NULL, NULL, NULL, NULL);
			return MurmurHash2A(status,6,6) != MurmurHash2A(STATUS_DEBUGGER_INACTIVE,6,6);

		}



		//Check Some value ( more info -> https://shhoya.github.io/antikernel_kerneldebugging4.html	)
		__forceinline	bool CheckGlobalValue()
		{

			auto kernelDebuggerPres = *(BYTE*)(0xFFFFF78000000000 + 0x02D4);

			auto 	KdEnteredDebugger = (PBOOLEAN)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("KdEnteredDebugger"));

			if (KdEnteredDebugger)
			{
				if (*KdEnteredDebugger)
					return true;
			}

			//	check value in KUSER_SHARED_DATA 
			if ((kernelDebuggerPres & 1) || (kernelDebuggerPres & 2))
			{
				return true;
			}

			return false;
		}

	}

}