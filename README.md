# MAJESTY-technologies
Little driver for protecthion.  
The driver is still under development, so you can submit your ideas!  
I write it's for manual map driver,because i havn't sertivicate for driver.  

Version 1.1


I try do this driver use max DKOM   
 
Anti-UM debug:  
1)PEPROCESS -> DebugPort  
2)PEPROCESS -> NoDebugInherit  
3)PETHREAD -> HideFromDebugger(set manual like:EAC)  
4)PEPROCESS -> InheritedFromUniqueProcessId and compare with explorer.exe  
  
Anti-analysis:  
1)Check InstrumentationCallback( PEPROCESS -> Pcb -> InstrumentationCallback)  
2)Do process proteced  
  
Anti-KM debug:  
1)Check offset(like:KdEnteredDebugger)  
2)Check KdFuncthion on return STATUS_DEBUGGER_INACTIVE  
  
Anti-Hypervisor:  
1)Time attack  
2)check anomalies  
  
To-do list:  
1)write communicathion(UM <-> KM)  
2)Use hash for get address NtApi  
3)Check some hook?  

Check instrumentation callbacks(under VMware) ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Detect%20instrumentation%20callbacks.png)  
Set protect process ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Protect%20Process.png)  
Running under HyperHide  ->  
![alt text](https://github.com/LazyAhora/MAJESTY-technologies/blob/main/Under%20HyperHide.png) 
