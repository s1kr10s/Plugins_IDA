#!/usr/bin/env python3
banner = '''
#---------------------------------------
#     Author: Miguel Mendez Z.
#     Twitter: @s1kr10s
#     For IDA: 7.4 to 7.6
#---------------------------------------
'''
print(banner)
print("\n...-=[Starting Search]=-...\n")

func_list = [
'strcpy','strcpyA','strcpyW','wcscpy','_tcscpy','_mbscpy','StrCpy','StrCpyA','StrCpyW','lstrcpy','lstrcpyA','lstrcpyW','_tccpy','_mbccpy','_ftcscpy',
'strcat','strcatA','strcatW','wcscat','_tcscat','_mbscat','StrCat','StrCatA','StrCatW','lstrcat','lstrcatA','lstrcatW','StrCatBuff','StrCatBuffA','StrCatBuffW','StrCatChainW',
'wvsprintf','wvsprintfA','wvsprintfW','vsprintf','_vstprintf','vswprintf',
'strncpy','wcsncpy','_tcsncpy','_mbsncpy','_mbsnbcpy','StrCpyN','StrCpyNA','StrCpyNW','StrNCpy','strcpynA','StrNCpyA','StrNCpyW','lstrcpyn','lstrcpynA','lstrcpynW'
'strncat','wcsncat','_tcsncat','_mbsncat','_mbsnbcat','StrCatN','StrCatNA','StrCatNW','StrNCat','StrNCatA','StrNCatW','lstrncat','lstrncatnA','lstrncatnW','lstrncatn',
'IsBadWritePtr','IsBadHugeWritePtr','IsBadReadPtr','IsBadHugeReadPtr','IsBadCodePtr','IsBadStringPtr',
'gets','_getts','_gettws',
'RtlCopyMemory','CopyMemory'
'wnsprintf','wnsprintfA','wnsprintfW','sprintfW','sprintfA','wsprintf','wsprintfW','wsprintfA','sprintf','swprintf','_stprintf','_snwpritf','_snprintf','_sntprintf',
'_vsnprintf','vsnprintf','_vsnwprintf','_vsntprintf','wvnsprintf','wvnsprintfA','wvnsprintfW',
'strtok','_tcstok','wcstok','_mbstok',
'makepath','_tmakepath','_makepath','_wmakepath'
'_splitpath','_tsplitpath','_wsplitpath',
'scanf','wscanf','_tscanf','sscanf','swscanf','_stscanf','snscanf','snwscanf','_sntscanf',
'_itoa','_itow','_i64toa','_i64tow','_ui64toa','_ui64tot','_ui64tow','_ultoa','_ultot','_ultow',
'calloc','malloc','memcpy','memmove','free','new','delete','recv','getenv']
func_list_rep = ['rep ','repe ','repne ','repnz ','repz ']
func_list_sys = ['system','execve','execvp','execlp','execle','execvpe']
func_list_cmp = ['strstr','strchr']

info = idaapi.get_inf_structure()
if info.is_64bit():
    print("    Binary: x64\n")
else:
    print("    Binary: x86\n")

print("*************************[FUNC]*************************\n")

cont_fun = 0
for f in func_list:
    for functionAddr in Functions():
        if f in get_func_name(functionAddr):
            cont_fun = 1
            print("    --------------" + f.upper() + "----------------")
            print("        ADDR: %s | FUNC: %s" % (hex(functionAddr), get_func_name(functionAddr)))
            xrefs = CodeRefsTo(functionAddr, False)
            for xref in xrefs:
                if print_insn_mnem(xref).lower() == "call":
                    print("        XREF: %s | FUNC: %s" % (hex(xref), get_func_name(functionAddr)))

if cont_fun == 0:
    print("        There are no records for FUNC")

print("\n*************************[REP]*************************\n")

ea = 0
cont_rep = 0
for r in func_list_rep:
    while ea != BADADDR:
        addr = find_text(ea+2,SEARCH_DOWN|SEARCH_NEXT, 0, 0, r);
        ea = addr
        if r in GetDisasm(addr):
            if GetDisasm(addr).find("ret") == -1:
                cont_rep = 1
                print("        ADDR: 0x%X | ASM: %s"%(addr, GetDisasm(addr)))

if cont_rep == 0:
    print("        There are no records for REP")

print("\n*************************[SYS]*************************\n")

cont_sys = 0
for s in func_list_sys:
    for functionAddr in Functions():
        if s in get_func_name(functionAddr):
            cont_sys = 1
            print("    --------------" + s.upper() + "----------------")
            print("        ADDR: %s | FUNC: %s" % (hex(functionAddr), get_func_name(functionAddr)))
            xrefs = CodeRefsTo(functionAddr, False)
            for xref in xrefs:
                if print_insn_mnem(xref).lower() == "call":
                    print("        XREF: %s | FUNC: %s" % (hex(xref), get_func_name(functionAddr)))

if cont_sys == 0:
    print("        There are no records for SYS")

print("\n*************************[STR]*************************\n")

cont_cmp = 0
for c in func_list_cmp:
    for functionAddr in Functions():
        if c in get_func_name(functionAddr):
            cont_cmp = 1
            print("    --------------" + s.upper() + "----------------")
            print("        ADDR: %s | FUNC: %s" % (hex(functionAddr), get_func_name(functionAddr)))
            xrefs = CodeRefsTo(functionAddr, False)
            for xref in xrefs:
                if print_insn_mnem(xref).lower() == "call":
                    print("        XREF: %s | FUNC: %s" % (hex(xref), get_func_name(functionAddr)))

if cont_cmp == 0:
    print("        There are no records for STR")

print("\n...-=[Search Finished]=-...\n")
