#pragma once
#include "Util.hpp"

namespace Offset
{
	DebugOffset  debugOffset;


	PprocOffset ppOffset;


	__forceinline uint64_t GetWindowsNumber()
	{

		RTL_OSVERSIONINFOW  lpVersionInformation{ 0 };

		lpVersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);



		auto   RtlGetVersion = (t_RtlGetVersion)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("RtlGetVersion"));

		if (RtlGetVersion)
		{
			RtlGetVersion(&lpVersionInformation);
		}
		else
		{
			PDWORD64 buildNumber = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("NtBuildNumber"));

			lpVersionInformation.dwBuildNumber = *buildNumber;
			lpVersionInformation.dwMajorVersion = *(ULONG*)0xFFFFF7800000026C;
			lpVersionInformation.dwMinorVersion = *(ULONG*)0xFFFFF78000000270;

		}

		if (lpVersionInformation.dwBuildNumber == WINDOWS_11)
		{
			return WINDOWS_11;
		}






		else if (lpVersionInformation.dwBuildNumber >= WINDOWS_10_VERSION_THRESHOLD1 && lpVersionInformation.dwBuildNumber <= WINDOWS_10_VERSION_21H1)
		{
			return WINDOWS_10;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8_1)
		{

			return WINDOWS_8_1;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8)
		{

			return WINDOWS_8;


		}
		else if (lpVersionInformation.dwBuildNumber == WINDOWS_7_SP1 || lpVersionInformation.dwBuildNumber == WINDOWS_7)
		{

			WINDOWS_7;

		}

	}



	__forceinline bool GetOffset()
	{


		RTL_OSVERSIONINFOW  lpVersionInformation{ 0 };




		lpVersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);



		auto   RtlGetVersion = (t_RtlGetVersion)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("RtlGetVersion"));

		if (RtlGetVersion)
		{
			RtlGetVersion(&lpVersionInformation);
		}
		else
		{
			PDWORD64 buildNumber = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr("NtBuildNumber"));

			lpVersionInformation.dwBuildNumber = *buildNumber;
			lpVersionInformation.dwMajorVersion = *(ULONG*)0xFFFFF7800000026C;
			lpVersionInformation.dwMinorVersion = *(ULONG*)0xFFFFF78000000270;

		}


		if (lpVersionInformation.dwBuildNumber == WINDOWS_11)
		{

			debugOffset.HideFromDebugger = 0x560;
			debugOffset.NoDebugInherit = 0x464;
			debugOffset.DebugPort = 0x578;
			debugOffset.InstrumentationCallback = 0x3d8;


			ppOffset.link = 0x448;
			ppOffset.pid = 0x440;
			ppOffset.name = 0x5a8;
			ppOffset.base = 0x520;
			ppOffset.protection = 0x87a;

			ppOffset.flags2 = 0x460;
			ppOffset.objecttable = 0x570;
			ppOffset.vadroot = 0x7d8;



		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_21H1 || lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_21H2 ||
			lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_20H2 || lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_20H1)
		{

			debugOffset.HideFromDebugger = 0x510;
			debugOffset.DebugPort = 0x578;
			debugOffset.NoDebugInherit = 0x464;
			debugOffset.InstrumentationCallback = 0x3d8;

			// link and pid UniqueProcessId
			ppOffset.link = 0x448;
			ppOffset.pid = 0x440;
			ppOffset.name = 0x5a8;
			ppOffset.base = 0x520;
			ppOffset.protection = 0x87a;

			ppOffset.flags2 = 0x460;
			ppOffset.objecttable = 0x570;
			ppOffset.vadroot = 0x7d8;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_19H2 || lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_19H1)
		{
			debugOffset.HideFromDebugger = 0x6e0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x30c;
			debugOffset.InstrumentationCallback = 0x2d0;


			ppOffset.link = 0x2f0;
			ppOffset.pid = 0x2e8;
			ppOffset.name = 0x448;
			ppOffset.base = 0x3c8;
			ppOffset.protection = 0x6fa;

			ppOffset.flags2 = 0x308;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x658;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE5)
		{

			debugOffset.HideFromDebugger = 0x6d0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;


			ppOffset.link = 0x2e8;
			ppOffset.pid = 0x2e0;
			ppOffset.name = 0x3c0;
			ppOffset.base = 0x3c8;
			ppOffset.protection = 0x6ca;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x628;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE4)
		{
			debugOffset.HideFromDebugger = 0x6d0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;


			ppOffset.link = 0x2e8;
			ppOffset.pid = 0x2e0;
			ppOffset.name = 0x450;
			ppOffset.base = 0x3c0;
			ppOffset.protection = 0x6ca;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x628;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE3)
		{
			debugOffset.HideFromDebugger = 0x6d0;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.DebugPort = 0x420;
			debugOffset.InstrumentationCallback = 0x2c8;



			ppOffset.link = 0x2e8;
			ppOffset.pid = 0x2e0;
			ppOffset.name = 0x450;
			ppOffset.base = 0x3c0;
			ppOffset.protection = 0x6ca;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x628;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
		{
			debugOffset.HideFromDebugger = 0x6c8;

			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;



			ppOffset.link = 0x2e8;
			ppOffset.pid = 0x2e0;
			ppOffset.name = 0x450;
			ppOffset.base = 0x3c0;
			ppOffset.protection = 0x6ca;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x628;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE1)
		{

			debugOffset.HideFromDebugger = 0x6c0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;


			ppOffset.link = 0x2f0;
			ppOffset.pid = 0x2e8;
			ppOffset.name = 0x450;
			ppOffset.base = 0x3c0;
			ppOffset.protection = 0x6c2;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x620;




		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_THRESHOLD2)
		{
			debugOffset.HideFromDebugger = 0x6bc;

			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;


			ppOffset.link = 0x2f0;
			ppOffset.pid = 0x2e8;
			ppOffset.name = 0x450;
			ppOffset.base = 0x3c0;
			ppOffset.protection = 0x6b2;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x610;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
		{
			debugOffset.HideFromDebugger = 0x6bc;

			debugOffset.DebugPort = 0x420;

			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;


			ppOffset.link = 0x2f0;
			ppOffset.pid = 0x2e8;
			ppOffset.name = 0x448;
			ppOffset.base = 0x3c0;
			ppOffset.protection = 0x6aa;

			ppOffset.flags2 = 0x300;
			ppOffset.objecttable = 0x418;
			ppOffset.vadroot = 0x608;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8_1)
		{

			debugOffset.HideFromDebugger = 0x6b4;

			debugOffset.DebugPort = 0x410;
			debugOffset.NoDebugInherit = 0x2fc;
			debugOffset.InstrumentationCallback = 0x2c0;


			ppOffset.name = 0x438;
			ppOffset.pid = 0x2E0;
			ppOffset.base = 0x3B0;
			ppOffset.link = 0x2E8;
			ppOffset.protection = 0x67A;
			ppOffset.flags2 = 0x2F8;
			ppOffset.objecttable = 0x408;
			ppOffset.vadroot = 0x5D8;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8)
		{

			debugOffset.HideFromDebugger = 0x42c;

			debugOffset.DebugPort = 0x410;
			debugOffset.NoDebugInherit = 0x2fc;
			debugOffset.InstrumentationCallback = 0x2c0;



			ppOffset.name = 0x438;
			ppOffset.pid = 0x2E0;
			ppOffset.base = 0x3B0;
			ppOffset.link = 0x2E8;
			ppOffset.protection = 0x648;
			ppOffset.flags2 = 0;
			ppOffset.objecttable = 0x408;
			ppOffset.vadroot = 0x590;



		}
		else if (lpVersionInformation.dwBuildNumber == WINDOWS_7_SP1 || lpVersionInformation.dwBuildNumber == WINDOWS_7)
		{

			debugOffset.HideFromDebugger = 0x448;
			debugOffset.DebugPort = 0x1f0;
			debugOffset.NoDebugInherit = 0x440;
			debugOffset.InstrumentationCallback = 0x100;



			ppOffset.name = 0x2D8;
			ppOffset.pid = 0x180;
			ppOffset.base = 0x270;
			ppOffset.link = 0x188;
			ppOffset.protection = 0x43C;
			ppOffset.flags2 = 0;
			ppOffset.objecttable = 0x200;
			ppOffset.vadroot = 0x448;

		}


		else
		{
			return FALSE;
		}

		return TRUE;

	}

}