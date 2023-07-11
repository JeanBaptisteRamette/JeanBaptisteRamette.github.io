---
title: "Analyzing anti-analysis features in gootkit"
layout: post
---

## Introduction

Hello there ! During my learning about malware-related subjects, I tend to watch a lot of videos from the Youtube channel [OA Labs](https://www.youtube.com/@OALABS), which is an absolutely amazing resource for everyone interested in malware ! Yesterday I was looking at an old [video](https://www.youtube.com/watch?v=QgUlPvEE4aw) from them which was focused on unpacking `Gootkit` and researching some of its anti-analysis tricks. At the end of the video, they leaves us to figure out the remaining anti-analysis tricks ourselves, I thought that would be a good thing to cover here and practice with, as the best way to learn is to get your hands dirty !

I suggest you grab the unpacked sample that I will be using [here](https://malshare.com/sample.php?action=detail&hash=f92aa495c4f932a1f0a7dd7669d592e4) so you can follow along, and maybe watch OALabs' video if you want more context. Anyway, I will be going over the check that was analyzed during the video again.

## Anti-analysis checks

If you have no experience at all with reverse-engineering, you probably wonder what are anti-analysis checks ? This simply refers to techniques used by malware authors (or legitimate software authors) to detect analysis attempts performed by reverse-engineers and alter the normal behavior of the program and/or making it harder to understand. Those checks are designed to identify debugging/analysis environments and react accordingly.

There are tons of anti-analysis techniques, and malware authors sometimes come out with quite interesting and clever methods, but I will give examples of some basic ones that you see a lot in the wild:

* Anti-debugging: malware may try to detect SW/HW breakpoints, debugging flags, or compute time comparisons between instructions to ensure the program is not being debugged.
* Time-based evasion: malware may try to avoid sandboxing services by sleeping through it before acting, until sandbox times out.
* Environment: malware may try to detect if it is being run in a virtual machine (for example with `cpuid` instruction), an emulated environment (such as Windows Defender's), or looking for virtualization artifacts like registry keys, filesystem, envvar...if one of those is detected, the malware may choose to stop its execution to avoid showing off its behavior.


In the main function of our gootkit sample, we have the following conditions:

![Exit conditions](/assets/blog-post-gootkit-anti-analysis/checks.png)

if the branch is taken, the program will exit early, which makes us not able to analyze it properly. Let's analyze the 3 functions, and determine what gootkit is checking for.


## Anti-analysis check n°1

We will start with the function covered in the video ``sub_408440``. Feel free to skip if you already know what it does.

The function is called with the full path of the executable of the current process.

```c++
int __stdcall sub_408440(LPCWSTR pszPath)
{
    int v2[10]; // [esp+0h] [ebp-44h]
    int v3; // [esp+28h] [ebp-1Ch]
    unsigned int v4; // [esp+2Ch] [ebp-18h]
    LPCWSTR v5; // [esp+30h] [ebp-14h]
    LPCWSTR lpString; // [esp+34h] [ebp-10h]
    int i; // [esp+38h] [ebp-Ch]
    LPCWSTR v8; // [esp+3Ch] [ebp-8h]

    lpString = PathFindFileNameW(pszPath);
    v3 = sub_40C990(lpString, -1);
    v2[0] = -1139578042;
    v2[1] = -666230612;
    v2[2] = -287798844;
    v2[3] = 1482907971;
    v2[4] = -1057857530;
    v2[5] = -2046378275;
    v2[6] = -389305480;
    v2[7] = 716628042;
    v2[8] = 837210602;
    v2[9] = 0;
    v8 = lpString;
    v5 = lpString + 1;
    while ( *v8++ )
        ;
    v4 = v8 - v5;
    if ( v4 >= 32 )
        return 1;
    for ( i = 0; v2[i]; ++i )
    {
        if ( v3 == v2[i] )
            return 1;
    }
    return 0;
}
```

The function will first retrieve the file name from the argument `lpString = PathFindFileNameW(pszPath);`, that is, the executable's name.
The funcion `sub_40C990` is called, which just converts the string from a wide string to a regular C string, and calls sub_40C180` with the converted string:

```c++
unsigned int __cdecl sub_40C180(LPCSTR FullPath, int PathSize)
{
    HANDLE v2; // eax
    HANDLE v3; // eax
    unsigned int v5; // [esp+8h] [ebp-10h]
    CHAR *lpMem; // [esp+Ch] [ebp-Ch]
    int FileNameSize; // [esp+10h] [ebp-8h]
    int slash_ptr; // [esp+14h] [ebp-4h]
    LPCSTR FileName; // [esp+14h] [ebp-4h]

    v5 = 0;
    if ( Path )
    {
        if ( PathSize == -1 )
            PathSize = lstrlenA(Path);

        // tries to retrieve a filename from the path
        slash_ptr = find_substring_from_end((int)Path, PathSize, '\\');
        if ( slash_ptr )
        {
            FileName = (LPCSTR)(slash_ptr + 1);
            FileNameSize = PathSize - (FileName - Path);
        }
        else
        {
            FileName = Path;
            FileNameSize = PathSize;
        }
        v2 = GetProcessHeap();
        lpMem = (CHAR *)HeapAlloc(v2, 8u, FileNameSize + 1);
        if ( lpMem )
        {
            if ( *FileName == '"' && FileName[FileNameSize - 1] == '"' )
            {
                FileNameSize -= 2;
                qmemcpy(lpMem, FileName + 1, FileNameSize);
                lpMem[FileNameSize] = 0;
            }
            else
            {
                qmemcpy(lpMem, FileName, FileNameSize);
                lpMem[FileNameSize] = 0;
            }
            to_uppercase(lpMem);
            v5 = sub_415BD0(lpMem, FileNameSize);
            v3 = GetProcessHeap();
            HeapFree(v3, 0, lpMem);
        }
    }
    return v5;
}
```

The function gets the file name (again), makes it uppercase and calls `sub_415BD0`, you have probably guessed it:

```c++
unsigned int __cdecl sub_415BD0(char *a1, int a2)
{
    unsigned int v4; // [esp+4h] [ebp-Ch]
    unsigned int i; // [esp+8h] [ebp-8h]
    unsigned int v6; // [esp+Ch] [ebp-4h]

    v6 = -1;
    while ( a2-- )
    {
        v4 = *a1++;
        for ( i = 0; i < 8; ++i )
        {
            if ( (((unsigned __int8)v4 ^ (unsigned __int8)v6) & 1) != 0 )
                v6 = (v6 >> 1) ^ 0xEDB88320;
            else
                v6 >>= 1;
            v4 >>= 1;
        }
    }
    return v6;
}
```

A hash function ! So we found out that `sub_40C990` computes the hash of the (uppercased) executable's name. Lookup the constant `0xEDB88320` and we know that it is a CRC-32 implementation.

Back in our `sub_408440` function we understand the following:

```c++
    hash = compute_filename_hash(lpString, -1);

    v2[0] = -1139578042;
    v2[1] = -666230612;
    v2[2] = -287798844;
    v2[3] = 1482907971;
    v2[4] = -1057857530;
    v2[5] = -2046378275;
    v2[6] = -389305480;
    v2[7] = 716628042;
    v2[8] = 837210602;
    v2[9] = 0;

    v8 = lpString;
    v5 = lpString + 1;
    while ( *v8++ );
    v4 = v8 - v5;
    if ( v4 >= 32 )
        return 1;
    for ( i = 0; v2[i]; ++i )
    {
        if ( hash == v2[i] )
            return 1;
    }
    return 0;
}
```

`v2` is an array of hashes for different filenames, the computed hash will be checked against each of them and if they match, the malware will exit.

```c++
  v8 = lpString;
  v5 = lpString + 1;
  
  while ( *v8++ );

  v4 = v8 - v5;

  if ( v4 >= 0x20 )
    return 1;
```

In addition, the function checks if the file name is longer than 32 characters, if it is, the malware probably considers that it has been downloaded from a malware uploading website and that the file name is probably the hash of the executable, thus being run for research purposes.

To know the names of the forbidden filenames, we need to bruteforce the hashes. Here is a really naive and unoptimized but working implementation for bruteforcing CRC32 hashes I made:

```c++
#include <unordered_set>
#include <string_view>
#include <iostream>
#include <string>


constexpr size_t FILENAME_MAX_LENGTH = 8;

std::unordered_set<size_t> hashes = {
                0xBC136B46,
                0xD84A20AC,
                0xEED889C4,
                0x58636143,
                0xC0F26006,
                0x8606BEDD,
                0xE8CBAB78,
                0x2AB6E04A,
                0x31E6D1EA,
            };


size_t crc32_hash(std::string_view data)
{
    size_t hash = - 1;

    size_t i = 0;
    size_t j = data.size();

    while (j--)
    {
        uint8_t byte = data[i++];

        for (uint8_t shift = 0; shift < 8; ++shift)
        {
            if (((byte ^ hash) & 1) != 0)
                hash = (hash >> 1) ^ 0xEDB88320;
            else
                hash >>=1 ;

            byte >>= 1;
        }
    }

    return hash;
}

void feed_hash(std::string_view source, std::string&& current)
{
    if (current.size() > FILENAME_MAX_LENGTH)
        return;

    const size_t hash = crc32_hash(current + ".EXE");

    if (hashes.contains(hash))
    {
        std::cout << "Found " << hash << " -> " << current << std::endl;
        hashes.erase(hash);

        if (hashes.empty())
            return;
    }

    for (const auto c : source)
        feed_hash(source, current + c);
}

int main()
{
    std::cout << std::hex;

    std::string_view source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    feed_hash(source, {});

    return 0;
}
```

It is slow because it does a lot of string allocation for concatenating the file extension `".EXE"`, but in counterpart we know in advance that there is only uppercase alphabetical characters and the maximum size of the strings from looking at OALabs video (a little cheating hehe), significantly decreasing the bruteforcing work. We get the following hashtable:

```
BOT.EXE = c0f26006
KLAVME.EXE = 8606bedd
MYAPP.EXE = e8cbab78
SAMPLE.EXE = bc136b46
SANDBOX.EXE = d84a20ac
MALWARE.EXE = eed889c4
TESTAPP.EXE = 2ab6e04a
```

Again, if the name of the executable under which the malware is running is one of these, it will stop it's execution, these names indicate that the user running the program knows it is a malware, and it is ran for analysis purposes. Another interesting name is `"myapp.exe"` which is the name under which process are emulated inside Windows Defender's antivirus emulator (I recommend ![this amazing talk](https://youtu.be/wDNQ-8aWLO0) by Alexei Bulazel from which I got this information). So the malware will detect if it's being run under Windows Defender and evade automated analysis by shutting down.

## Anti-analysis check n°2

Here is what we have so far:

![Exit conditions](/assets/blog-post-gootkit-anti-analysis/checks2.png)

Now let's investigate one of the check that was not covered in the video, `sub_40B700`:

```c++
int sub_40B700()
{
    const CHAR *v0; // eax
    int v1; // eax
    CHAR Buffer[260]; // [esp+8h] [ebp-12Ch] BYREF
    int v4; // [esp+10Ch] [ebp-28h]
    int v5; // [esp+110h] [ebp-24h]
    void *v6; // [esp+114h] [ebp-20h] BYREF
    char v7[16]; // [esp+118h] [ebp-1Ch]
    char v8[8]; // [esp+128h] [ebp-Ch] BYREF
    int i; // [esp+130h] [ebp-4h]

    v5 = 0;
    memset(Buffer, 0, sizeof(Buffer));
    v7[0] = 17;
    v7[1] = 42;
    v7[2] = 88;
    v7[3] = 25;
    v7[4] = 47;
    v7[5] = 31;
    v7[6] = 61;
    v7[7] = 86;
    v7[8] = 22;
    v7[9] = 43;
    v7[10] = 30;
    v7[11] = 55;
    v7[12] = 57;
    qmemcpy(v8, "rX9zD", 5);
    sub_402150(13);
    for ( i = 0; i < 13; ++i )
        sub_402130(&v6, i, v8[i % 5] ^ v7[i]);
    v0 = (const CHAR *)sub_402120(&v6);
    if ( GetEnvironmentVariableA(v0, Buffer, 0x104u) )
    {
        v1 = lstrlenA(Buffer);
        if ( crc32_hash(Buffer, v1) == 0x964B360E )
            v5 = 1;
    }
    v4 = v5;
    sub_402180(&v6);
    return v4;
}
```

We get a stack string usage, which is xored, `sub_402150`, `sub_402180`, and `sub_402130` are just string operations:

* `sub_402150`: allocates a n bytes string
* `sub_402180`: deallocates the string
* `sub_402130`: copy byte to buffer

We can easily resolve the stack string: 

```python
def decode_stack_string(chars, key):
    decoded = ""

    for i in range(len(chars)):
        decoded += chr(chars[i] ^ ord(key[i % len(key)]))

    return decoded

print(decode_stack_string([17, 42, 88, 25, 47, 31, 61, 86, 22, 43, 30, 55, 57], "rX9zD"))
```

And we get the string `"crackmeololo"`, the malware checks if the CRC32 hash of the environment variable `"crackmeololo"` content matches 0x964B360E. Honestly, I haven't bothered bruteforcing the input this time, because it can be really anything..
If the content matches, the malware will skip the other checks, so actually, this function is not really an anti-analysis feature, it is just used to run the anti-analysis checks or not...I haven't found any reference to where the `"crackmeololo"` environment variable might be set, so it has probably no logical meaning, the author probably just left this as a troll.

## Anti-analysis check n°3

![](/assets/blog-post-gootkit-anti-analysis/checks3.png)

Digging into `sub_407FE0`, we eventually find the following code:

```c++
    ...
    if ( !NtQuerySystemInformation )
    {
        // ntdll.dll
        v7[0] = 94;
        v7[1] = 19;
        v7[2] = 93;
        v7[3] = 35;
        v7[4] = 88;
        v7[5] = 30;
        v7[6] = 3;
        qmemcpy(v8, "U#4", sizeof(v8));
        qmemcpy(v10, "0g9O4", 5);
        string_allocate(&v15, 10);
        for ( i = 0; i < 10; ++i )
            string_set_at(&v15, i, v10[i % 5] ^ v7[i]);

        // NtQuerySystemInformation
        v6[0] = 13;
        v6[1] = 60;
        v6[2] = 24;
        v6[3] = 5;
        v6[4] = 60;
        v6[5] = 49;
        v6[6] = 49;
        v6[7] = 26;
        v6[8] = 9;
        v6[9] = 42;
        v6[10] = 55;
        v6[11] = 45;
        v6[12] = 36;
        v6[13] = 57;
        v6[14] = 55;
        v6[15] = 37;
        v6[16] = 39;
        v6[17] = 59;
        v6[18] = 29;
        v6[19] = 56;
        v6[20] = 55;
        v6[21] = 33;
        v6[22] = 38;
        v6[23] = 30;
        v6[24] = 89;
        qmemcpy(v9, "CHIpY", 5);
        string_allocate(&v16, 25);
        for ( j = 0; j < 25; ++j )
            string_set_at(&v16, j, v9[j % 5] ^ v6[j]);
        v5 = get_string(&v16);
        v2 = get_string(&v15);
        v3 = LoadLibraryA(v2);
        NtQuerySystemInformation = GetProcAddress(v3, v5);
        string_free(&v16);
        string_free(&v15);
    }
    ...
```

The malware dynamically resolves `NtQuerySystemInformation` 

```c++
    //
    // Request size first
    //
    NtStatus = NtQuerySystemInformation(SystemProcessInformation, 0, 0, &dwSize);
    if ( NtStatus == STATUS_INFO_LENGTH_MISMATCH )
    {
        dwSize += 256;
        pProcInfo = VirtualAlloc(0, dwSize, 0x3000u, 4u);
        if ( pProcInfo )
        {
            //
            // Query process list information
            //
            NtStatus = NtQuerySystemInformation(SystemProcessInformation, pProcInfo, dwSize, 0);
            if ( NtStatus >= 0 )
            {
                ProcessInformation = pProcInfo;
                v13 = 0;
                while ( 1 )
                {
                    if ( ProcessInformation->UniqueProcessId )
                    {
                        //
                        // PID 4 -> Windows System
                        //
                        if ( ProcessInformation->UniqueProcessId != 4
                          && ProcessInformation->UniqueProcessId != MalwarePid )
                        {
                            wow64 = call_IsWow64Process(ProcessInformation->UniqueProcessId, 0);
                            hash = compute_filename_hash(
                                       ProcessInformation->ImageName.Buffer,
                                       ProcessInformation->ImageName.Length >> 1);

                            if ( !compare_hash(
                                      ProcessInformation->ImageName.Buffer,
                                      hash,
                                      ProcessInformation->UniqueProcessId,
                                      ProcessInformation->InheritedFromUniqueProcessId,
                                      wow64,
                                      a2) )
                                break;
                        }
                    }
    ................
```
and calls it with the information class `SystemProcessInformation`, from MSDN:

>Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system. These structures contain information about the resource usage of each process, including the number of threads and handles used by the process, the peak page-file usage, and the number of memory pages that the process has allocated.

The malware will iterate over each process (skipping itself and the Windows SYSTEM process), and compare (via hash) process names with a list of forbidden processes.
However, in the sample we have (the one provided by OALabs), there is no hashlist to compare against, I thought it might be a decompilation failure, but looking at the disassembly it is not, even by debugging the loop is not executed, which is kind of weird...Anyway, we can quite safely assume that it is supposed to be an anti-VM check, on other versions of the loader, this function is quite probably looking for specific processes running in sandbox environment.

Digging a little bit more into the loader, I found out that this process enumeration function was not only used for anti-analysis purposes, but also for process injection ! So I will cover it briefly:

![](/assets/blog-post-gootkit-anti-analysis/main_function_thread_creation.png)

Before the end of the main function, Gootkit creates a thread responsible for installing the JavaScript payload (Gootkit is divided into multiple stages, we are only looking at the loader).

![](/assets/blog-post-gootkit-anti-analysis/required_process_check.png)

The installation setup only starts if `sub_407F70` returns false, meaning it is checking for some important predicate.

![](/assets/blog-post-gootkit-anti-analysis/process_check_navigator.png)

From looking at this, We immediatly recognize the pattern we had seen before looking for running processes by hash. The difference is this time, Gootkit absolutely needs these processes to be running in order to proceed its attacks. If a malware needs a process to be running, it most of the time means that it is going to inject into it.

We have to think about what Gootkit targets: knowing that Gootkit is a banking trojan, we can assume that the loader would want to inject into a browser to intercept communications between victims and their bank. From this assumption we compute the CRC-32 hash of a widely used browser process, for example: Firefox.

`crc32("FIREFOX.EXE") = 0x662D9D39` and we get a match ! From there, we can make a list of known browser processes, took me a few minutes to gather, but we get the following hashtable:

```
MICROSOFTEDGE.EXE   = aea3ed09
MICROSOFTEDGECP.EXE = 2993125a
OPERA.EXE           = 3d75a3ff
FIREFOX.EXE         = 662d9d39
IEXPLORE.EXE        = 922df04
CHROME.EXE          = c84f40f0
SAFARI.EXE          = dcfc6e80
```

(It mostly took me time because the sample is not recent, and since then, browsers names changed, I was looking for `msedge.exe` instead of the legacy version `microsoftedge.exe`..)


I wanted to show this even though it's not related to anti-analysis because it demonstrates the process enumeration used by Gootkit.


## Post-checks behavior 

Another thing that was not covered in OALabs video was this function:

![Post check function](/assets/blog-post-gootkit-anti-analysis/last_functions.png)

This function is called if one of the two anti-analysis functions returns true, before exit. It decrypts a stack string containing the following batch script (MS-DOS command script):

```bat
attrib -r -s -h %%1
:%u
del %%1
if exist %%1 goto %u
del %%0
```

(%u is a C format specifier)

The commands first removes readonly, system, and hidden attributes to the file passed as an argument, then loops until the file has been deleted, once it has been the batch script removes itself from the filesystem.

The malware copies its executable path to a buffer and decrypts the string "%lu.bat", this time varying it's decoding, by merging the xor key and the encoded bytes together. It proceeds by replacing the filename from the buffer, to create the script file inside the same directory.
```c
lstrcpyW(script_path, executable_path);    // "C:\\path\\gootkit.exe"
script_filename = last_index_of(script_path, '\\') + 1;
// 0-16  xor key
// 17-22 encoded bytes
qmemcpy(v22, "gi(1E3li&1Q36iD1BiD103", 22);

string_allocate(fmt_string, 32);
for ( i = 0; i < 16; ++i )
    string_set_at(fmt_string, i, v22[i % 6 + 16] ^ v22[i]);
time = GetTickCount();  
format = get_string(fmt_string);         // "C:\\path\\%lu.bat"
wsprintfW(script_filename, format, time);       // give it a random name
```

The script content is then written into a file in the same directory as the malware. TODO: Investigate why changing the filetime is used ?

The malware next resolves `ShellExecuteW` from `shell32.dll`, to launch the batch script with the malware executable path as argument. Resulting in deleting the malware executable, then the script itself.

## Additional anti-analysis checks

TODO