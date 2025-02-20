#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <string>
#include <iostream>

#pragma comment(lib, "Fwpuclnt")

bool blocked = 0;


wchar_t* GetWC(const char* c)
{
    size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];

    size_t convertedChars = 0;
    errno_t err = mbstowcs_s(&convertedChars, wc, cSize, c, cSize - 1);

    if (err != 0)
    {
        delete[] wc;
        return nullptr;
    }

    return wc;
}



int main() {

    std::cout << "FWPM Basic\n";

    HANDLE engineHandle;
    
    if (DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle))
        std::cout << "fwpm engine Failed\n";
    
    FWPM_FILTER0 filterV4In, filterV4Out, filterV6In, filterV6Out;
    SecureZeroMemory(&filterV4In, sizeof(filterV4In));
    SecureZeroMemory(&filterV4Out, sizeof(filterV4Out));
    SecureZeroMemory(&filterV6In, sizeof(filterV6In));
    SecureZeroMemory(&filterV6Out, sizeof(filterV6Out));

    FWPM_FILTER_CONDITION0 conditions[2];
    conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[0].conditionValue.type = FWP_UINT8;
    conditions[0].conditionValue.uint8 = 17;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[1].fieldKey = FWPM_CONDITION_DIRECTION;
    conditions[1].conditionValue.type = FWP_UINT32;
    conditions[1].matchType = FWP_MATCH_EQUAL;

    while (true)
    {
        while (true)
        {
            if (GetAsyncKeyState(VK_XBUTTON1) & 0x8000 && !blocked)
            {
                //IPv4 inbound
                filterV4In.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
                conditions[1].conditionValue.uint32 = FWP_DIRECTION_INBOUND;
                filterV4In.filterCondition = conditions;
                filterV4In.action.type = FWP_ACTION_BLOCK;
                filterV4In.displayData.name = GetWC("FWPM_block_v4_in");
                filterV4In.numFilterConditions = 2;
                filterV4In.weight.type = FWP_EMPTY;
                if (DWORD result = FwpmFilterAdd0(engineHandle, &filterV4In, NULL, &filterV4In.filterId))
                    std::cout << "fwpm block IPv4 inbound Failed\n";

                //IPv4 outbound
                filterV4Out.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
                conditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;
                filterV4Out.filterCondition = conditions;
                filterV4Out.action.type = FWP_ACTION_BLOCK;
                filterV4Out.displayData.name = GetWC("FWPM_block_v4_out");
                filterV4Out.numFilterConditions = 2;
                filterV4Out.weight.type = FWP_EMPTY;
                if (DWORD result = FwpmFilterAdd0(engineHandle, &filterV4Out, NULL, &filterV4Out.filterId))
                    std::cout << "fwpm block IPv4 outbound Failed\n";

                //IPv6 inbound
                filterV6In.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6;
                conditions[1].conditionValue.uint32 = FWP_DIRECTION_INBOUND;
                filterV6In.filterCondition = conditions;
                filterV6In.action.type = FWP_ACTION_BLOCK;
                filterV6In.displayData.name = GetWC("FWPM_block_v6_in");
                filterV6In.numFilterConditions = 2;
                filterV6In.weight.type = FWP_EMPTY;
                if (DWORD result = FwpmFilterAdd0(engineHandle, &filterV6In, NULL, &filterV6In.filterId))
                    std::cout << "fwpm block IPv6 inbound Failed\n";

                //IPv6 outbound
                filterV6Out.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6;
                conditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;
                filterV6Out.filterCondition = conditions;
                filterV6Out.action.type = FWP_ACTION_BLOCK;
                filterV6Out.displayData.name = GetWC("FWPM_block_v6_out");
                filterV6Out.numFilterConditions = 2;
                filterV6Out.weight.type = FWP_EMPTY;
                if (DWORD result = FwpmFilterAdd0(engineHandle, &filterV6Out, NULL, &filterV6Out.filterId))
                    std::cout << "fwpm block IPv6 outbound Failed\n";

                blocked = true;
                Beep(1000, 100);

            }
            else if (GetAsyncKeyState(VK_XBUTTON1) & 0x8000 && blocked)
            {
                if (DWORD result = FwpmFilterDeleteById0(engineHandle, filterV4In.filterId))
                    std::cout << "fwpm release IPv4 inbound Failed\n";
                if (DWORD result = FwpmFilterDeleteById0(engineHandle, filterV4Out.filterId))
                    std::cout << "fwpm release IPv4 outbound Failed\n";
                if (DWORD result = FwpmFilterDeleteById0(engineHandle, filterV6In.filterId))
                    std::cout << "fwpm release IPv6 inbound Failed\n";
                if (DWORD result = FwpmFilterDeleteById0(engineHandle, filterV6Out.filterId))
                    std::cout << "fwpm release IPv6 outbound Failed\n";

                blocked = false;
                Beep(1000, 100);
            }
        }
        Sleep(100);
    }
}