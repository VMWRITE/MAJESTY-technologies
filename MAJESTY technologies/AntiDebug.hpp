#pragma once

#include "GetPID.h"

#include "AntiHypervisor.hpp"
#include "Offset.hpp"

namespace AntiDebug
{

	namespace AntiUserModeAntiDebug
	{
		//Just check DebugPort in PEPROCESS
		__forceinline	bool PsIsProcessBeingDebugged(const char* procName)
		{


			uint64_t IsdebugPort = 0;
			auto procID = PIDHelp::GetID(procName);
			if (procID)
			{
				PEPROCESS proc;


				auto PsLookupProcessByProcessId = (t_PsLookupProcessByProcessId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("PsLookupProcessByProcessId"));

				if (NT_SUCCESS(PsLookupProcessByProcessId(procID, &proc)))
				{

					IsdebugPort = *(uint32_t*)((uint64_t)proc + Offset::debugOffset.DebugPort);



					auto myObfReferenceObject = (t_ObfReferenceObject)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("ObfReferenceObject"));
					myObfReferenceObject(proc);
				}
			}
			return IsdebugPort;

		}







		//Just check NoDebugInherit  in PEPROCESS
		__forceinline	bool IsProcessDebugFlag(const char* procName)
		{
			/*

			NoDebugInherit safe  if  debugger detaches?
			*/


			BYTE IsDebugFlag = 0;
			auto procID = PIDHelp::GetID(procName);
			if (procID)
			{
				PEPROCESS proc;


				auto PsLookupProcessByProcessId = (t_PsLookupProcessByProcessId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("PsLookupProcessByProcessId"));

				if (NT_SUCCESS(PsLookupProcessByProcessId(procID, &proc)))
				{
					IsDebugFlag = (*(ULONG*)((uint64_t)proc + Offset::debugOffset.NoDebugInherit)) & 0x2;


					auto myObfReferenceObject = (t_ObfReferenceObject)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("ObfReferenceObject"));
					myObfReferenceObject(proc);
				}
			}
			return IsDebugFlag != 0;

		}

		__forceinline bool IsInstrCallbacks(const char* procName)
		{
			uint64_t IsInstEnable = 0;
			auto procID = PIDHelp::GetID(procName);
			if (procID)
			{
				PEPROCESS proc;


				auto PsLookupProcessByProcessId = (t_PsLookupProcessByProcessId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("PsLookupProcessByProcessId"));

				if (NT_SUCCESS(PsLookupProcessByProcessId(procID, &proc)))
				{
					IsInstEnable = (*(uint64_t*)((uint64_t)proc + Offset::debugOffset.InstrumentationCallback));


					auto myObfReferenceObject = (t_ObfReferenceObject)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("ObfReferenceObject"));
					myObfReferenceObject(proc);
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

			auto KdDisableDebugger = (t_KdDisableDebugger)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("KdDisableDebugger"));
			return KdDisableDebugger() != STATUS_DEBUGGER_INACTIVE;

			// https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html

		}

		//Call ZwSystemDebugControl with SysDbgBreakPoint
		__forceinline bool DebugTrigger()
		{

			//	https://pastebin.com/6kbt1Vka



			auto ZwSystemDebugControl = (t_ZwSystemDebugControl)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("ZwSystemDebugControl"));
			NTSTATUS status = ZwSystemDebugControl(
				SysDbgBreakPoint,
				0,
				0,
				0,
				0,
				0
			);

			return status != STATUS_DEBUGGER_INACTIVE;
		}

		//Call KdChangeOption like Vanguard  -> https://www.unknowncheats.me/forum/2798056-post2.html
		__forceinline	bool IsChangeOpthion()
		{

			auto KdChangeOption = (t_KdChangeOption)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("KdChangeOption"));
			auto status = KdChangeOption(KD_OPTION_SET_BLOCK_ENABLE, NULL, NULL, NULL, NULL, NULL);
			return status != STATUS_DEBUGGER_INACTIVE;

		}



		//Check Some value ( more info -> https://shhoya.github.io/antikernel_kerneldebugging4.html	)
		__forceinline	bool CheckGlobalValue()
		{

			auto kernelDebuggerPres = *(BYTE*)(0xFFFFF78000000000 + 0x02D4);

			PBOOLEAN 	KdEnteredDebugger = (PBOOLEAN)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("KdEnteredDebugger"));

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