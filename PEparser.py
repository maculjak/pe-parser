import os

#This function converts numbers stored in little endian to human-readable format
def convert_little_endian(hex, l):
    retval = ""
    for i in range(0, l, 2):
        retval += hex[-(i+2)] + hex[-(i+1)]
    return '0x' + retval

#This function is used to print data stored in fields of headers
def print_line(name, size, index):
    output = "\t" + name + ":"
    for i in range(26 - len(name)):
        output += " "
    print(output + convert_little_endian(text[index:index + size], size))
    return index + size

#This function is used to find a section where import directories reside
def where_is_import_table(sec, rva):
    retval = ""
    for k in sec:
        if rva < sec[k]:
            return retval
        retval = k
    return retval

#This funciton does the same work as where_is_import_table, but I am using it to find the export table, hence the name
def where_is_export_table(secrva, rva):
    return where_is_import_table(secrva, rva)

#This function also does the same work as where_is_import_table, but the name implies that it is used to find any RVA
def where_is_address(secrva, rva):
    return where_is_import_table(secrva, rva)

#This function calculates physical offset of RVA based on following formula:
#PHYSICAL OFFSET = RVA - SECTION RVA + POINTER TO RAW DATA
#In my code I have been multiplying calcualted physical offset by two because I haven't been reading text of a file
#as an array of bytes, but as a string where every nibble is one character.
def calculate_physical_offset(rva, secrva, ptr):
    return rva - secrva + ptr

print("Enter the name or a full path of a file you want to parse if it is in the same folder as this program:", end=" ")

while True:
    try:
        file_to_parse = open(input(), "rb")
        break
    except FileNotFoundError:
        print("File not found. Please try again.")
        continue

text = file_to_parse.read()
text = ''.join('{:02X}'.format(c) for c in text)

index = 0

############################################################################
#                                MZ header                                 #
############################################################################

print("MZ header\n=========")
index = print_line("Magic", 4, index)
index = print_line("BytesOnLastPageOfFile", 4, index)
index = print_line("PagesInFile", 4, index)
index = print_line("Relocations", 4, index)
index = print_line("SizeOfHeaderInParagraphs", 4, index)
index = print_line("MinimumExtraParagraphs", 4, index)
index = print_line("MaximumExtraParagraphs", 4, index)
index = print_line("InitialSS", 4, index)
index = print_line("InitialSP", 4, index)
index = print_line("Checksum", 4, index)
index = print_line("InitialIP", 4, index)
index = print_line("InitialCS", 4, index)
index = print_line("OffsetToRelocationTable", 4, index)
index = print_line("OverlayNumber", 4, index)

for i in range(4):
    index = print_line("Reserved", 4, index)

index = print_line("OEMIdentifier", 4, index)
index = print_line("OEMInformation", 4, index)

for i in range(10):
    index = print_line("Reserved", 4, index)

print_line("OffsetToNewExeHeader", 8, index)
index = 2*int((convert_little_endian(text[index:index+8], 8)[2:]), 16)

############################################################################
#                                PE header                                 #
############################################################################

print("\nPE header\n=========")
index = print_line("Magic", 8, index)
index = print_line("Machine", 4, index)
number_of_section_headers = int(convert_little_endian(text[index:index+4],4)[2:],16)
index = print_line("NumberOfSections", 4, index)
index = print_line("TimeDateStamp", 8, index)
index = print_line("PointerToSymbolTable", 8, index)
index = print_line("NumberOfSymbols", 8, index)
index = print_line("SizeOfOptionalHeader", 4, index)
index = print_line("Characteristics", 4, index)

############################################################################
#                              Optional header                             #
############################################################################

print("\nOptional header\n===============")

optional_header_magic = convert_little_endian(text[index:index+4], 4)
index = print_line("Magic", 4, index)
index = print_line("MajorLinkerVersion", 2, index)
index = print_line("MinorLinkerVersion", 2, index)
index = print_line("SizeOfCode", 8, index)
index = print_line("SizeOfInitializedData", 8, index)
index = print_line("SizeOfUninitializedData", 8, index)
index = print_line("AddressOfEntryPoint", 8, index)
index = print_line("BaseOfCode", 8, index)
index = print_line("BaseOfData", 8, index)

image_base = int(convert_little_endian(text[index:index+8],8)[2:], 16)

index = print_line("ImageBase", 8, index)
index = print_line("SectionAlignment", 8, index)
index = print_line("FileAlignment", 8, index)
index = print_line("MajorOSVersion", 4, index)
index = print_line("MinorOSVersion", 4, index)
index = print_line("MajorImageVersion", 4, index)
index = print_line("MinorImageVersion", 4, index)
index = print_line("MajorSubsystemVersion", 4, index)
index = print_line("MinorSubsystemVersion", 4, index)
index = print_line("Win32VersionValue", 8, index)
index = print_line("SizeOfImage", 8, index)
index = print_line("SizeOfHeaders", 8, index)
index = print_line("Checksum", 8, index)
index = print_line("Subsystem", 4, index)
index = print_line("DLLCharacteristics", 4, index)
index = print_line("SizeOfStackReserve", 8, index)
index = print_line("SizeOfStackCommit", 8, index)
index = print_line("SizeOfHeapReserve", 8, index)
index = print_line("SizeOfHeapCommit", 8, index)
index = print_line("LoaderFlags", 8, index)
index = print_line("NumberOfDataDirectories", 8, index)

print("\tEXPORT Table")
export_table_rva = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("\tRVA", 8, index)
export_table_size = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("\tSize", 8, index)

print("\tIMPORT Table")
import_table_rva = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tRESOURCE Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tEXCEPTION Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tCERTIFICATE Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tBASE RELOCATION Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tDEBUG Directory")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tArchitecture Specific Data")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tGLOBAL POINTER Register")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tTLS Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tLOAD CONFIGURATION Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tBOUND IMPORT Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tIMPORT Address Table")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tDELAY IMPORT Descriptors")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print("\tCLI Header")
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

print()
index = print_line("\tRVA", 8, index)
index = print_line("\tSize", 8, index)

############################################################################
#                              Section headers                             #
############################################################################

print("Section headers\n===============")

pointers_to_raw_data = {}
section_rvas = {}

for i in range(number_of_section_headers):
    print("\tName:", end="")
    for j in range(22):
        print(end=" ")
    name = bytearray.fromhex(text[index:index + 16].lstrip("0")).decode()
    print(name)
    index += 16
    index = print_line("VirtualSize", 8, index)

    section_rvas[name] = int(convert_little_endian(text[index:index+8],8)[2:], 16)

    index = print_line("RVA", 8, index)
    index = print_line("SizeOfRawData", 8, index)

    pointers_to_raw_data[name] = int(convert_little_endian(text[index:index+8],8)[2:], 16)

    index = print_line("PointerToRawData", 8, index)
    index = print_line("PointerToRelocations", 8, index)
    index = print_line("PointerToLineNumbers", 8, index)
    index = print_line("NumberOfRelocations", 4, index)
    index = print_line("NumberOfLineNumbers", 4, index)
    index = print_line("Characteristics", 8, index)
    print()

############################################################################
#                             Import table                                 #
############################################################################

if optional_header_magic == "0x020B":
    print("File is 64-bit, therefore only limited view is provided.\n")
    os.system('PAUSE')
    exit(0)

there = where_is_import_table(section_rvas, import_table_rva)
physical_offset = calculate_physical_offset(import_table_rva, section_rvas[there], pointers_to_raw_data[there])
index = 2 * physical_offset

print("Import table\n============")

while convert_little_endian(text[index:index+8], 8) != "0x00000000":
     print("\n\tImport directory\n\t================")
     index = print_line("\tImportNameTableRVA", 8, index)
     index = print_line("\tTimeDateStamp", 8, index)
     index = print_line("\tForwarderChain", 8, index)

     name_rva = int(convert_little_endian(text[index:index+8],8)[2:], 16)
     name_physical_offset = 2 * calculate_physical_offset(name_rva, section_rvas[there], pointers_to_raw_data[there])
     index = print_line("\tNameRVA", 8, index)

     print("\t\tLibraryName:", end = "")
     for j in range(14):
         print(end=" ")

     i = name_physical_offset
     while True:
         hexcharacter = text[i:i+2]
         if hexcharacter == "00":
             break
         character = bytearray.fromhex(hexcharacter).decode()
         print(character, end = "")
         i += 2
     print()

     import_address_table_rva = int(convert_little_endian(text[index:index + 8], 8)[2:], 16)
     import_address_table_physical_offset = 2 * calculate_physical_offset(import_address_table_rva, section_rvas[there], pointers_to_raw_data[there])

     index = print_line("\tImportAddressTableRVA", 8, index)
     print()
     print("\t\tImport Thunks\n\t\t================")
     i = import_address_table_physical_offset

     while True:
         output_string = "\t\t\tApi: "
         if convert_little_endian(text[i:i+8], 8)[2] != "0":
             print("\t\t\tApi: ", end="")
             print(convert_little_endian(text[i:i+8], 8), end="")
             print(" Ordinal: " + convert_little_endian(text[i:i+4], 4))
             i += 8
             continue

         function_name_rva = convert_little_endian(text[i:i + 8], 8)
         output_string += function_name_rva + " "
         function_name_rva = int(function_name_rva, 16)
         function_name_physical_offset = calculate_physical_offset(function_name_rva, section_rvas[there], pointers_to_raw_data[there])

         output_string += "(phys: " + str.format('0x{:08X}', function_name_physical_offset) + ") hint: "

         function_name_physical_offset *= 2
         j = function_name_physical_offset

         if text[j:j+8]  == "00000000" or j <= 0:
             break

         hint = convert_little_endian(text[j:j+4], 4)
         output_string += hint + ", Name: "
         j += 4

         function_name = ""
         while text[j:j+2] != "00" and j > 0:
             function_name += bytearray.fromhex(text[j:j+2]).decode()
             j += 2

         output_string += function_name + " "
         print(output_string)
         i += 8

############################################################################
#                             Export table                                 #
############################################################################

print("Export Table\n============")
if export_table_size == 0:
    print("\tExport table does not exist\n")
    os.system('PAUSE')
    exit(0)

there = where_is_export_table(section_rvas, export_table_rva)
physical_offset = calculate_physical_offset(export_table_rva, section_rvas[there], pointers_to_raw_data[there])
index = 2 * physical_offset

print("\tExport Directory\n\t================")

index = print_line("Characteristics", 8, index)
index = print_line("TimeDateStamp:", 8, index)
index = print_line("MinorVersion", 4, index)
index = print_line("MajorVersion", 4, index)

name_rva = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("NameRVA", 8, index)
name_physical_offset = 2 * calculate_physical_offset(name_rva, section_rvas[there], pointers_to_raw_data[there])
i = name_physical_offset

print("\tLibraryName:               ", end="")

while text[i:i+2] != "00":
    print(bytearray.fromhex(text[i:i+2]).decode(), end="")
    i += 2

function_names = i + 2
print()
ordinal_base = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("OrdinalBase", 8, index)

number_of_functions = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("NumberOfFunctions", 8, index)

number_of_names = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("NumberOfNames", 8, index)

address_table_rva = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
index = print_line("AddressTableRVA", 8, index)

name_pointer_table_rva = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
name_pointer_table_physical_offset = 2 * calculate_physical_offset(name_pointer_table_rva, section_rvas[there], pointers_to_raw_data[there])
index = print_line("NamePointerTableRVA", 8, index)

ordinal_table_rva = int(convert_little_endian(text[index:index+8], 8)[2:], 16)
ordinal_table_offset = 2 * calculate_physical_offset(ordinal_table_rva, section_rvas[there], pointers_to_raw_data[there])
index = print_line("OrdinalTableRVA", 8, index)

address_table_physical_offset = 2 * calculate_physical_offset(address_table_rva, section_rvas[there], pointers_to_raw_data[there])
k = name_pointer_table_physical_offset
ordinals_and_names = {}
ordinals_and_function_name_addresses = {}
ordinals_and_physical_offsets = {}
ordinals_index = ordinal_table_offset

for i in range (number_of_names):
    ordinal = ordinal_base + int(convert_little_endian(text[ordinals_index:ordinals_index+4],4),16)
    function_name_rva = int(convert_little_endian(text[k:k+8], 8), 16)
    ordinals_and_function_name_addresses[hex(ordinal)] = convert_little_endian(text[k:k+8], 8)
    function_name_physical_offset = 2 * calculate_physical_offset(function_name_rva, section_rvas[there], pointers_to_raw_data[there])
    ordinals_and_physical_offsets[hex(ordinal)] = function_name_physical_offset

    l = function_name_physical_offset
    name = ""
    while text[l:l+2] != "00":
        name += bytearray.fromhex(text[l:l+2]).decode()
        l += 2

    ordinals_and_names[hex(ordinal)] = name
    ordinals_index += 4
    k += 8

print("\n\t\tExport address table\n\t\t====================")

j = address_table_physical_offset

for i in range(number_of_functions):
    ordinal = hex(ordinal_base + i)
    output_string = "\t\t\tApi: "

    function_rva = convert_little_endian(text[j:j+8], 8)
    output_string += convert_little_endian(text[j:j+8], 8)

    here = where_is_address(section_rvas, int(function_rva[2:], 16))

    output_string += " (phys: "
    output_string += str.format('0x{:08X}', calculate_physical_offset(int(function_rva[2:], 16), section_rvas[here], pointers_to_raw_data[here]))
    output_string += ") "
    output_string += "--> Ordinal: " + str.format('0x{:04X}', i)
    output_string += " Name: "

    if ordinal in ordinals_and_names:
        output_string += ordinals_and_names[ordinal]

    print(output_string)
    j += 8

print("\n\t\tFunction name table\n\t\t====================")

for i in range(number_of_functions):
    ordinal = hex(ordinal_base + i)
    if ordinal not in ordinals_and_function_name_addresses:
        continue

    print("\t\t\tApi: ", ordinals_and_function_name_addresses[ordinal], end = "")
    offset = str.format('0x{:08X}', ordinals_and_physical_offsets[ordinal])
    print(" (phys: " + offset + ") ", end = "")
    print("Name: " + ordinals_and_names[ordinal])

print("\n\t\tFunction name table\n\t\t====================")

for i in range(number_of_functions):
    print("\t\t\tValue: " + str(hex(i)), end = "")
    decoded_ordinal =  str.format('0x{:04X}', int(i + ordinal_base))
    print("(decoded ordinal: " + decoded_ordinal + ") ", end = "")
    print("Name: ", end = "")

    if hex(i + ordinal_base) not in ordinals_and_names:
        continue

    print(ordinals_and_names[hex(i + ordinal_base)])

print()
os.system('PAUSE')