#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <imgread.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    struct Image img;
    memcpy(&img, Data, min(Size, sizeof(img)));
    process_image(&img);
    return 0;  // Values other than 0 and -1 are reserved for future use.
}

#ifdef __cplusplus
}
#endif
