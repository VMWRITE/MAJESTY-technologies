#pragma once
#include  "Offset.hpp"
#include "GetPID.h"



// original https://github.com/notscimmy/pplib
namespace PplibEx
{

	void ProtectProcessByName(const char* procName)
	{




		PEPROCESS proc;
		auto procID = PIDHelp::GetID(procName);
		auto PsLookupProcessByProcessId = (t_PsLookupProcessByProcessId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("PsLookupProcessByProcessId"));

		if (NT_SUCCESS(PsLookupProcessByProcessId(procID, &proc)))
		{
			BYTE* pEProcess = (BYTE*)proc;
			uint8_t* pPPL = pEProcess + Offset::ppOffset.protection;

			uint64_t  version = Offset::GetWindowsNumber();
			if (version == WINDOWS_7 || version == WINDOWS_7_SP1)
				*(DWORD*)pPPL |= 1 << 0xB;
			else if (version == WINDOWS_8)
				*pPPL = true;
			else if (version == WINDOWS_8_1 || version == WINDOWS_10 || version == WINDOWS_11)
			{ 
				PS_PROTECTION protection;
				protection.Flags.Signer = PsProtectedSignerWinTcb;
				protection.Flags.Type = PsProtectedTypeProtected;
				*pPPL = protection.Level;
			}

			auto myObfReferenceObject = (t_ObfReferenceObject)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("ObfReferenceObject"));
			myObfReferenceObject(proc);
		}


	}

}