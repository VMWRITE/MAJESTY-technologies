#pragma once

#include "Util.hpp"

//	https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html



namespace DetectHyp
{
	

	__forceinline	bool compare_list_cpuid()
	{
		//compare cpuid  list
		int  invalid_cpuid_list[4] = { -1 };
		int valid_cpuid_list[4] = { -1 };

		__cpuid(invalid_cpuid_list, 0x13371337);
		__cpuid(valid_cpuid_list, 0x40000000);

		if ((invalid_cpuid_list[0] != valid_cpuid_list[0]) ||
			(invalid_cpuid_list[1] != valid_cpuid_list[1]) ||
			(invalid_cpuid_list[2] != valid_cpuid_list[2]) ||
			(invalid_cpuid_list[3] != valid_cpuid_list[3]))
			return true;

		return false;



	}

	__forceinline bool cpuid_is_hypervisor()
	{
		int cpuid[4] = { 0 };
		__cpuid(cpuid, 1);
		return ((cpuid[2] >> 31) & 1);
	}



	bool   time_attack_rdtsc()
	{
		unsigned long  tick1 = 0;
		unsigned long tick2 = 0;
		unsigned long avg = 0;
		int cpuInfo[4] = {};
		for (int i = 0; i < 2500; i++)
		{
			tick1 = __readmsr(IA32_TIME_STAMP_COUNTER);
			__cpuid(cpuInfo, 0);// vm-exit
			tick2 = __readmsr(IA32_TIME_STAMP_COUNTER);
			avg += (tick2 - tick1);
		}
		avg /= 2500;
		return (avg < 500 && avg > 25) ? false : true;
	}




	// Some hypervisor just  0(like:VMware)
	bool time_attack_MPERF()
	{


		int cpuid[4]{ -1 };
		DWORD64  avg{ 0 };
		for (size_t i = 0; i < 2500; i++)
		{
			auto tick1 = __readmsr(IA32_MPERF_MSR);
			__cpuid(cpuid, 0);//call vm-exit
			auto tick2 = __readmsr(IA32_MPERF_MSR);
			avg += (tick2 - tick1);
		}
		avg /= 2500;
		return  (0xff < avg) || (0xc > avg);
	}


	// Some hypervisor just return 0(like:VMware)
	bool time_attack_APERF()
	{

		DWORD64 avg{ 0 };
		int data[4]{ -1 };

		for (size_t i = 0; i < 2500; i++)
		{
			DWORD64 tick1 = __readmsr(IA32_APERF_MSR) << 32;
			__cpuid(data, 0); //call vm-exit
			DWORD64 tick2 = __readmsr(IA32_APERF_MSR) << 32;

			avg += (tick2 - tick1);

		}
		avg /= 2500;
		return   (avg < 0x00000BE30000) || (avg > 0x00000FFF0000000);
	}

	__forceinline bool lbr_is_virtulazed()
	{
		DWORD64 current_value = __readmsr(MSR_DEBUGCTL);//safe current value
		__writemsr(MSR_DEBUGCTL, DEBUGCTL_LBR | DEBUGCTL_BTF);
		DWORD64 whatch_write = __readmsr(MSR_DEBUGCTL);
		__writemsr(MSR_DEBUGCTL, current_value);
		return (!(whatch_write & DEBUGCTL_LBR));
	}

	__forceinline bool lbr_stask_is_virtulazed()
	{
		int cpuid[4]{ -1 };
		auto currentLBR = __readmsr(MSR_P6M_LBSTK_TOS);
		__cpuid(cpuid, 0);//call vm-exit
		auto exitLBR = __readmsr(MSR_P6M_LBSTK_TOS);
		return currentLBR != exitLBR;

	}




}