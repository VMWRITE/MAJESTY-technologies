#pragma once
#include  "Offset.hpp"
#include "GetPID.h"



/*
	original https://github.com/notscimmy/pplib

	more info https://guidedhacking.com/threads/protected-processes-light-protected-processes.14968/

*/
namespace PplibEx
{

	__forceinline	void ProtectProcessByPID(HANDLE procId)
	{
		PEPROCESS proc; 
		 
		if (procId &&  NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
		{
			BYTE* pEProcess = (BYTE*)proc;
			uint8_t* pPPL = pEProcess + Offset::ppOffset.protection;

			uint64_t  version = Offset::GetWindowsNumber();
			if (version == WINDOWS_NUMBER_7)
				*(DWORD*)pPPL |= 1 << 0xB;
			else if (version == WINDOWS_NUMBER_8)
				*pPPL = true;
			else if (version == WINDOWS_NUMBER_8_1)
			{ 
				PS_PROTECTION protection;
				protection.Flags.Signer = PsProtectedSignerWinSystem;// = PsProtectedSignerMax for Windows 8.1
				protection.Flags.Type = PsProtectedTypeMax;
				*pPPL = protection.Level;
			}

			// process hacker can't sea PsProtectedTypeMax  and write Unknown	? WTF?!
			else if (version == WINDOWS_NUMBER_10 || version == WINDOWS_NUMBER_11)
			{
				PS_PROTECTION protection; 
				protection.Flags.Signer = PsProtectedSignerMax;
				protection.Flags.Type = PsProtectedTypeMax;
				*pPPL = protection.Level;
			}
			 
		}


	}

}