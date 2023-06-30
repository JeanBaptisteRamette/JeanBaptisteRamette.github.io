---
title: "Detect and bypass API Hashing: How malware developers hide their imports"
layout: post
---


## Introduction

Hi ! Today we are going to talk about API hashing, something you have probably came across multiple times when reverse engineering malwares. I'm going to show you how we can implement API hashing, detect it, and bypass it !

Usually one of the first thing you do when analyzing a binary is taking a look at the PE Import Table, letting you know what possible functionalities the sample has (is it doing some networking, file handling, process injection, modifying registry keys, unpacking ...?). For this reason, a threat actor really wants to obfuscate his product, making it more difficult to analyze...

This is where API hashing appears. Let's take a look at a simple binary I made to demonstrate the technique.

## The Analyst's View
Let's look at the import table of the sample and see what we can learn about the executable:

![PE Imports](/assets/blog-post-apihashing/imports.png)

mmmh...We do not see anything interesting in this table...The imports listed here are just used to generate a stack cookie and initializing the Microsoft C Runtime Library (search "scrt_commain_main_seh" if you want to learn more about that).

If we run the executable (it is not malicious :D), it drops a `"demo.txt"` file, yet we did not see any `CreateFile`/`WriteFile` or any lower level equivalent API call. How is this possible..?

The main function is pretty straight forward:

![Main Function Prologue](/assets/blog-post-apihashing/main1.png)

It calls `sub_140001000` with two integers as arguments three times and check that the return values (`rbx`, `rdi`, `rsi`) are not null else it exits.

![Post check](/assets/blog-post-apihashing/main2.png)

If they all do not return 0, it will call the values returned by the function (`rbx`, `rdi`, `rsi`), then exits. The disassembly can be translated to the pseudocode:

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

We guess from the behavior of the program that `v1` is the function opening the file, `v2` writes to it and `v3` closes it.
This means that the malware is doing some kind of dynamic API resolving (retrieving the functions at runtime).


## Theory

Before seeing from the malware developer's view to explain the implementation, a little theory on what you need to know before understanding API hashing

### The Process Environment Block

Wikipedia defines it well:
The Process Environment Block (abrreviated PEB) is a data structure in the Windows NT operating system family. It is an opaque data structure that is used by the operating system internally, most of whose fields are not intended for use by anything other than the operating system. [...] The PEB contains data structures that apply across a whole process, including global context, startup parameters, data structures for the program image loader, the program image base address....

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


### Hashing

Hashing is the process of transforming input data into a fixed-size value, called a "hash" or a "digest". The two key characteristics that are really important for our use-case is that it is:

1. Deterministic: Hashing the same input will always give the same digest, which is important for comparisons.
2. Irreversibility: Hashing functions are one-way, you can not find the input from the output without bruteforcing with all possible inputs. This is important for the malware developer, it's not some xor string cyphering.


### The PE Export Table

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

We will now walk through the original source of the executable to put it all together and see how this is done.
