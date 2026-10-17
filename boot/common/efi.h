/* Minimal UEFI definitions written for this project from the UEFI 2.11
 * specification (sections 4, 7, 12). Only what boot/ needs. Freestanding C.
 * Calling convention: UEFI uses the Microsoft x64 ABI; we compile with
 * -target x86_64-unknown-windows so plain C functions already match it. */
#ifndef NAWAH_EFI_H
#define NAWAH_EFI_H

#include "types.h"

#define EFIAPI
#define EFI_SUCCESS            0ULL
#define EFI_ERROR_BIT          (1ULL << 63)
#define EFI_BUFFER_TOO_SMALL   (EFI_ERROR_BIT | 5)
#define EFI_INVALID_PARAMETER  (EFI_ERROR_BIT | 2)
#define EFI_ERROR(s)           (((INTN)(s)) < 0)

typedef struct { UINT32 Data1; UINT16 Data2; UINT16 Data3; UINT8 Data4[8]; } EFI_GUID;

typedef struct {
    UINT64 Signature; UINT32 Revision; UINT32 HeaderSize; UINT32 CRC32; UINT32 Reserved;
} EFI_TABLE_HEADER;

/* ---- Simple Text Output (12.4) ---- */
struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_TEXT_STRING)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_RESET)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN ExtendedVerification);
typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_TEXT_RESET Reset; EFI_TEXT_STRING OutputString; VOID *TestString; VOID *QueryMode; VOID *SetMode;
    VOID *SetAttribute; VOID *ClearScreen; VOID *SetCursorPosition; VOID *EnableCursor; VOID *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/* ---- Memory map (7.2) ---- */
typedef enum {
    EfiReservedMemoryType, EfiLoaderCode, EfiLoaderData, EfiBootServicesCode, EfiBootServicesData,
    EfiRuntimeServicesCode, EfiRuntimeServicesData, EfiConventionalMemory, EfiUnusableMemory,
    EfiACPIReclaimMemory, EfiACPIMemoryNVS, EfiMemoryMappedIO, EfiMemoryMappedIOPortSpace, EfiPalCode,
    EfiPersistentMemory, EfiUnacceptedMemoryType, EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef struct {
    UINT32 Type; UINT32 Pad; EFI_PHYSICAL_ADDRESS PhysicalStart; EFI_VIRTUAL_ADDRESS VirtualStart;
    UINT64 NumberOfPages; UINT64 Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef enum { AllocateAnyPages, AllocateMaxAddress, AllocateAddress, MaxAllocateType } EFI_ALLOCATE_TYPE;

/* ---- Boot Services (7) — only the slots we call are typed; the rest keep the layout. ---- */
typedef EFI_STATUS (EFIAPI *EFI_GET_MEMORY_MAP)(UINTN *MemoryMapSize, EFI_MEMORY_DESCRIPTOR *MemoryMap, UINTN *MapKey, UINTN *DescriptorSize, UINT32 *DescriptorVersion);
typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_POOL)(EFI_MEMORY_TYPE PoolType, UINTN Size, VOID **Buffer);
typedef EFI_STATUS (EFIAPI *EFI_FREE_POOL)(VOID *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle, UINTN MapKey);
typedef EFI_STATUS (EFIAPI *EFI_STALL)(UINTN Microseconds);

typedef struct {
    EFI_TABLE_HEADER Hdr;
    VOID *RaiseTPL; VOID *RestoreTPL;
    VOID *AllocatePages; VOID *FreePages; EFI_GET_MEMORY_MAP GetMemoryMap; EFI_ALLOCATE_POOL AllocatePool; EFI_FREE_POOL FreePool;
    VOID *CreateEvent; VOID *SetTimer; VOID *WaitForEvent; VOID *SignalEvent; VOID *CloseEvent; VOID *CheckEvent;
    VOID *InstallProtocolInterface; VOID *ReinstallProtocolInterface; VOID *UninstallProtocolInterface; VOID *HandleProtocol;
    VOID *Reserved; VOID *RegisterProtocolNotify; VOID *LocateHandle; VOID *LocateDevicePath; VOID *InstallConfigurationTable;
    VOID *LoadImage; VOID *StartImage; VOID *Exit; VOID *UnloadImage; EFI_EXIT_BOOT_SERVICES ExitBootServices;
    VOID *GetNextMonotonicCount; EFI_STALL Stall; VOID *SetWatchdogTimer;
    VOID *ConnectController; VOID *DisconnectController;
    VOID *OpenProtocol; VOID *CloseProtocol; VOID *OpenProtocolInformation;
    VOID *ProtocolsPerHandle; VOID *LocateHandleBuffer; VOID *LocateProtocol; VOID *InstallMultipleProtocolInterfaces; VOID *UninstallMultipleProtocolInterfaces;
    VOID *CalculateCrc32; VOID *CopyMem; VOID *SetMem; VOID *CreateEventEx;
} EFI_BOOT_SERVICES;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    VOID *GetTime; VOID *SetTime; VOID *GetWakeupTime; VOID *SetWakeupTime;
    VOID *SetVirtualAddressMap; VOID *ConvertPointer;
    VOID *GetVariable; VOID *GetNextVariableName; VOID *SetVariable;
    VOID *GetNextHighMonotonicCount; VOID *ResetSystem;
    VOID *UpdateCapsule; VOID *QueryCapsuleCapabilities; VOID *QueryVariableInfo;
} EFI_RUNTIME_SERVICES;

typedef struct { EFI_GUID VendorGuid; VOID *VendorTable; } EFI_CONFIGURATION_TABLE;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor; UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle; VOID *ConIn;
    EFI_HANDLE ConsoleOutHandle; EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle; EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
    EFI_RUNTIME_SERVICES *RuntimeServices; EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries; EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;

#endif
