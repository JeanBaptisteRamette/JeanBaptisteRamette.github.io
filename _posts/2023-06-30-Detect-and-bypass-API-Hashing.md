---
title: "Detect and bypass API Hashing: How malware developers hide their imports"
layout: post
mathjax: true
---


## Introduction

Hi ! Today we are going to talk about API hashing, something you have probably came across multiple times when reverse engineering malwares. I'm going to show you how we can implement API hashing, detect it, and bypass it !

Usually one of the first thing you do when analyzing a binary is taking a look at the PE Import Table, letting you know what possible functionalities the sample has (is it doing some networking, file handling, process injection, modifying registry keys, unpacking ...?). For this reason, a threat actor really wants to obfuscate his product, making it more difficult to analyze...

This is where API hashing appears. Let's take a look at a simple binary I made to demonstrate the technique.

## The Analyst's View
Let's look at the import table of the sample and see what we can learn about the executable:

![PE Imports](/assets/blog-post-apihashing/imports.png)

mmmh...We do not see anything interesting in this table...The imports listed here are just used to generate a stack cookie and initializing the Microsoft C Runtime Library (search "scrt_commain_main_seh" if you want to learn more about that).

If we run the executable (it is not malicious :D), it drops a file named `"demo.txt"`, yet we did not see any `CreateFile`/`WriteFile` or any lower level equivalent API call. How is this possible..? Keep digging in the main function which is pretty straight forward:

![Main Function Prologue](/assets/blog-post-apihashing/main1.png)

It calls `sub_140001000` with two integers as arguments three times and check that the return values (`rbx`, `rdi`, `rsi`) are not null else it exits.

![Post check](/assets/blog-post-apihashing/main2.png)

If none of them return 0, it will call the values returned by the function (`rbx`, `rdi`, `rsi`), then exits. The disassembly can be translated to the pseudocode:

```c
main()
{
    v1 = sub_140001000(0x15490331, 0x18E6042C);
    v2 = sub_140001000(0x15490331, 0x191C0443);
    v3 = sub_140001000(0x15490331, 0x11C8038C);

    if (v1 && v2 && v3)
    {
        v4 = v1("demo.txt", 4, 1);

        v5 = 0;
        v2(v4, "What does this do ?", 19, &v5, 0);

        v3(v4);
    }
}
```

We guess from the behavior of the program that and arguments that `v1` is the function opening the file, `v2` writes to it and `v3` closes it.
This means that the malware is doing some kind of dynamic API resolving (retrieving the functions at runtime), the value `0x15490331` probably being the hash of a module name, and the second arguments the hash of a function name.


## Theory

Before seeing from the malware developer's view to explain the implementation, a little theory on what you need to know before understanding API hashing is recommended.

### 1- The Process Environment Block

Wikipedia defines it well:
> The Process Environment Block (abrreviated PEB) is a data structure in the Windows NT operating system family. It is an opaque data structure that is used by the operating system internally, most of whose fields are not intended for use by anything other than the operating system. [...] The PEB contains data structures that apply across a whole process, including global context, startup parameters, data structures for the program image loader, the program image base address....

The PEB basically stores information about a running process, the 64-bit version of the structure is poorly documented by Microsoft (though it has been fully reversed for multiple kernel versions):

```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB;
```

There are a lot of interesting fields in this structure we could talk about, but what we are interested in right now is the `LoaderData` field, which holds a linked list of modules loaded for the process.

You can access the PEB through an assembly stub or an intrinsic function only, on Windows for the x64 architecture, a pointer to the PEB is located at offset `0x60` in the `GS` segment:
```c++
reinterpret_cast<PNT_PEB64>(__readgsqword(0x60));
```

```asm
mov rax, qword ptr gs:[60]
```


### 2 - Hashing

Hashing is the process of transforming input data into a fixed-size value, called a "hash" or a "digest". The two key characteristics that are really important for our use-case is that it is:

1. Deterministic: Hashing the same input will always give the same digest, which is important for comparisons. Mathematically: $$ h(x_1) = h(x_2) \iff x_1 = x_2 $$ 
   Although in practice, depending on the algorithm, collisions may happen more or less meaning: $$ h(x_1) = h(x_2) \land x_1 \neq x_2 $$
2. Irreversibility: Hashing functions are one-way, you can not find the input from the output without bruteforcing with all possible inputs. This is important for the malware developer, it's not some xor string cyphering.


### 3 - The PE Export Table

The PE Export Table (or Export Directory) is a data structure contained inside PE files (mainly DLLs). It basically holds a table of functions that can be accessed by other modules. It is defined as:

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

The field `AddressOfFunctions` is essentially the EAT (Export Address Table).

When you load a procedure from a DLL with the famous function `GetProcAddress`, it will simply walk through the EAT of the module, compare the function names and return the function's address.


## The Malware Developer's View

We will now walk through the original source of the executable to put it all together and see how this is done. Here is the main function of the sample we looked at in IDA:

```c++
int main(int argc, char** argv)
{
    constexpr auto DigestModule      = SymHash(L"KERNEL32.DLL");
    constexpr auto DigestCreateFileW = SymHash("CreateFileW");
    constexpr auto DigestCloseHandle = SymHash("CloseHandle");
    constexpr auto DigestWriteFile   = SymHash("WriteFile");

    const auto CreateFileW = ResolveAPI<pCreateFileW>(DigestModule, DigestCreateFileW);
    const auto CloseHandle = ResolveAPI<pCloseHandle>(DigestModule, DigestCloseHandle);
    const auto WriteFile   = ResolveAPI<pWriteFile>(DigestModule, DigestWriteFile);

    if (CreateFileW && CloseHandle && WriteFile)
    {
        HANDLE FileHandle = CreateFileW(L"demo.txt",
                                        FILE_APPEND_DATA,
                                        FILE_SHARE_READ,
                                        nullptr,
                                        OPEN_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL,
                                        nullptr);

        DWORD dwBytesWritten {};

        WriteFile(FileHandle, "What does this do ?", 19, &dwBytesWritten, nullptr);

        CloseHandle(FileHandle);
    }


    return 0;
}
```

First, the malware calculates the hashes of the symbols that we wish to use, it uses the quite convenient C++ keyword `constexpr`  which suggests the compiler to evaluate code at compile time.
That way, the malware developer still has the symbols that where hashed but they won't appear in the binary.

In our case, the SymHash function is just a simple Adler-32 hash implementation, it takes a string as input and returns a 4 bytes integer.

```c++
// Make a template because module names are stored as wide strings in the PEB
// and we want to be able to use normal strings for convenience
template<typename char_type>
constexpr uint32_t SymHash(char_type* Symbol)
{
    // Adler32 hash implementation
    constexpr uint16_t MOD_ADLER = 0xFFF1;

    uint32_t csum1 = 1;
    uint32_t csum2 = 0;

    for (const char_type c : std::basic_string_view<char_type>(Symbol))
    {
        csum1 = (csum1 +     c) % MOD_ADLER;
        csum2 = (csum2 + csum1) % MOD_ADLER;
    }

    return (csum2 << 16) | csum1;
}
```

The important part is the `ResolveAPI` function:

```c++
template<typename Function>
Function ResolveAPI(uint32_t ModuleHash, uint32_t ProcedureHash)
{
    NT_LDR_DATA_TABLE_ENTRY* const Module = ResolveInMemoryModule(ModuleHash);

    if (!Module)
        return nullptr;

    void* Proc = ResolveProcedure((LPBYTE)Module->DllBase, ProcedureHash);

    if (Proc == nullptr)
        return nullptr;

    return reinterpret_cast<Function>(Proc);
}
```

It will call `ResolveInMemoryModule` which will search for a certain module in the PEB, known as PEB walking:

```c++
PNT_LDR_DATA_TABLE_ENTRY ResolveInMemoryModule(uint32_t ModuleHash)
{
    const auto Peb = NtCurrentPeb();
    const auto LoaderData = Peb->Ldr;

    // circular doubled linked list of all modules loaded for the process
    const LIST_ENTRY* Head = &LoaderData->InMemoryOrderModuleList;
    const LIST_ENTRY* ModuleNode = nullptr;

    // walk through the list
    for (ModuleNode = Head->Flink; ModuleNode != Head ; ModuleNode = ModuleNode->Flink)
    {
        const auto LoadedModule = CONTAINING_RECORD(ModuleNode, NT_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
        const auto ModuleName = LoadedModule->BaseDllName.Buffer;

        if (SymHash(ModuleName) == ModuleHash)
            return LoadedModule;
    }

    return nullptr;
}
```

The important line here is the `SymHash` call, Sym
