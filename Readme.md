# LoadThatPE

![LoadThatPE](.assets/virustotal-v3.png)

> A polymorphic in-memory PE loader. Encodes, obfuscates, and executes a PE 
> entirely from memory — no file written to disk.

## 🚀 Features

- **RC4 stream cipher encryption** — payload encrypted with a derived RC4 key, XOR-free, less pattern-recognizable than simple XOR loops
- **DLL section stomping** — instead of anonymous `VirtualAlloc` regions (easily flagged), the encrypted payload is written directly into the `.text` section of a large legitimate DLL (`ieframe.dll` or equivalent), making the memory region appear backed by a real DLL on disk
- **Polymorphic chunking** — payload split into randomly-sized chunks stored in shuffled order, unique binary on every generation
- **In-memory execution** — decrypts, maps, resolves imports, relocates sections and transfers execution via a new thread
- **SHA-256 Proof-of-Work** — ~40–50s anti-sandbox delay before execution
- **Stack strings** — sensitive API names (`LoadLibraryA`, `GetProcAddress`, `VirtualProtect`...) built char-by-char at runtime
- **Full identifier randomization** — all C++ function/variable names randomized at generation time
- **DLL candidate scanner** — `check_dll.py` scans `System32` to identify DLLs with a `.text` section large enough to stomp the target payload

---

# LoadThatAssembly

![LoadThatAssembly](.assets/loadthatassembly_demo.png)

## ✨ Features

LoadThatAssembly is a native (C/C++) CLR host that:

- Embeds an obfuscated .NET assembly in the binary (encryptedPE)
- Decrypts it in memory via XOR and validates it is a .NET PE (DOS/PE signatures + COM/CLR directory)
- Initializes CLR v4 using ICLRMetaHost/ICLRRuntimeInfo and starts ICorRuntimeHost
- Opens the Default AppDomain and loads the assembly directly from a SAFEARRAY
- Retrieves the entry point and invokes it, passing the process arguments as a string[]

Everything is performed fully in memory; no file is written to disk.

> **⚠️ About AMSI/ETW patching**  
> Before loading the assembly, the program calls:  
> **patchScanBuffer()**: patches AmsiScanBuffer in amsi.dll  
> **patchEcritureEvent()**: patches EtwEventWrite in ntdll.dll

---

This tool is strictly for **educational and research purposes**. Misuse of this tool 
for malicious or unauthorized activities is strictly prohibited. Respect the laws 
and ethical guidelines of your jurisdiction.

---

## 🛠️ Installation

### LoadThat-PE (Word Dictionary Edition)

```bash
git clone https://github.com/ProcessusT/LoadThat-PEandAssembly.git
cd LoadThatPE
python3 encrypt_pe.py <YOUR_PE.exe>

# requirements
apt install mingw-w64
pip3 install pefile requests
```
![LoadThatPE](.assets/example.png)


### LoadThat-Assembly

```bash
git clone https://github.com/ProcessusT/LoadThat-PEandAssembly.git
cd LoadThatAssembly
python3 encrypt_pe.py <YOUR_PE.exe> <encrypted_pe.txt>
```
Then, replace "unsigned char encryptedPE[]", "size_t encryptedPESize" and "const unsigned char xorKey" into the loader and compile !


## Disclaimer

This release is purely for educational and research purposes. Use responsibly.