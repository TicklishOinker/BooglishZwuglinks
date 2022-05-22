# JeeglishRuggle
A simple R/W driver using IOCTLs.  

Driver: BinklyTroink.c  
Usermode interface: Frigabriggle.h  

Features:  
Get process base address  
Get EPROCESS address  
Copy Memory  

Security features:  
Creates strings on the stack (Both in driver and usermode interface)  
