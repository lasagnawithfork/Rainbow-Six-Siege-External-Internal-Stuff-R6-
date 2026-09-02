# Rainbow-Six-Siege-External-Internal-Stuff-R6-
R6



Information about new anti cheat :
- new script detection

 Service called "sen_service" appears to be Ubisoft anti-cheat service
 As far as we know there is also **RING 0** DETECTION while not confirmed, it is very high-likely; 
 

I will also continue updating this source too after some time
  this repository will contain

   External Source Code fully working.
    Internal Source code I'm not really familiar with therefore There's a very unlikely chance I'll even bother with it

  High in depth is that r6 uses sigs. 
   This is all I've identified for now 
   88e15f23:WorldToScreen
   ***Current WorldToScreenClassID**

  I'm doing allot of research about R6 Generally posting information and sources if I get my hands on the knowledge behind it.


## HOW TO FIND GAME MANAGER

Open ida with your game build.
Search R6TextChatManager -> XREF IT ->  jump to addy sub_blabla_

**v26 ^ v27 = game manager it's always added or 3xb something similar  the letter in the middle can change over patches or seasons.



---

##  Random Pattern Scanner Source Code
```c++
#pragma once
#include "../../Includes.h"

#define Pattern_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2A6, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _pattern_scan {
    INT32 ProcessId;
    ULONGLONG StartAddress;
    ULONGLONG Size;
    UCHAR Pattern[256];
    UCHAR Mask[256];
    ULONG PatternLength;
    ULONGLONG ResultAddress;
} pattern_scan, * ppattern_scan;

namespace PatternScan
{
    inline NTSTATUS ScanPattern(ppattern_scan req)
    {
        if (!req || req->PatternLength == 0 || req->PatternLength > 256)
            return STATUS_INVALID_PARAMETER;

        req->ResultAddress = 0;

        PEPROCESS TargetProcess = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &TargetProcess);
        if (!NT_SUCCESS(status))
            return status;

        KAPC_STATE apc;
        KeStackAttachProcess(TargetProcess, &apc);

        __try
        {
            const ULONGLONG chunk_size = 0x100000;
            for (ULONGLONG offset = 0; offset < req->Size; offset += chunk_size)
            {
                ULONGLONG current_chunk_size = (chunk_size < (req->Size - offset)) ? chunk_size : (req->Size - offset);
                PVOID scan_addr = (PVOID)(req->StartAddress + offset);

                if (!MmIsAddressValid(scan_addr))
                    continue;

                for (ULONGLONG i = 0; i < current_chunk_size - req->PatternLength; i++)
                {
                    PUCHAR current = (PUCHAR)((ULONGLONG)scan_addr + i);
                    
                    if (!MmIsAddressValid(current))
                        continue;

                    BOOLEAN found = TRUE;
                    for (ULONG j = 0; j < req->PatternLength; j++)
                    {
                        if (req->Mask[j] == 'x')
                        {
                            if (!MmIsAddressValid(current + j) || current[j] != req->Pattern[j])
                            {
                                found = FALSE;
                                break;
                            }
                        }
                    }

                    if (found)
                    {
                        req->ResultAddress = (ULONGLONG)current;
                        KeUnstackDetachProcess(&apc);
                        ObDereferenceObject(TargetProcess);
                        return STATUS_SUCCESS;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(TargetProcess);
            return STATUS_ACCESS_VIOLATION;
        }

        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(TargetProcess);
        return STATUS_NOT_FOUND;
    }
}
```


