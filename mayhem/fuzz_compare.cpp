#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "data_view.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str1 = provider.ConsumeRandomLengthString();
    std::string str2 = provider.ConsumeRandomLengthString();
    protozero::data_view dv1(str1);
    protozero::data_view dv2(str2);

    dv1.compare(dv2);

    return 0;
}
