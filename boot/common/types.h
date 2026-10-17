/* Freestanding fixed-width types shared by boot/ and kernel/. No firmware definitions here. */
#ifndef NAWAH_TYPES_H
#define NAWAH_TYPES_H
typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef unsigned long long UINT64;
typedef UINT64          UINTN;
typedef long long       INTN;
typedef UINT8           BOOLEAN;
typedef UINT16          CHAR16;
typedef void            VOID;
typedef UINTN           EFI_STATUS;
typedef VOID           *EFI_HANDLE;
typedef VOID           *EFI_EVENT;
typedef UINT64          EFI_PHYSICAL_ADDRESS;
typedef UINT64          EFI_VIRTUAL_ADDRESS;

#endif
