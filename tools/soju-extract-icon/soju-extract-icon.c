/*
 * soju-extract-icon - Extract icons from Windows PE files
 *
 * Pure C, no dependencies, works on Unix/Linux/macOS
 *
 * Usage: soju-extract-icon <input.exe> <output.png>
 *
 * Output: PNG file (direct extraction if icon is PNG, otherwise ICO wrapper)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* PE structures */
#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;      /* MZ */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;     /* Offset to PE header */
} DOS_HEADER;

typedef struct {
    uint32_t Signature;    /* PE\0\0 */
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PE_HEADER;

typedef struct {
    uint16_t Magic;        /* 0x10b = PE32, 0x20b = PE32+ */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} OPTIONAL_HEADER32;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DATA_DIRECTORY;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
} RESOURCE_DIR;

typedef struct {
    uint32_t NameOrId;
    uint32_t OffsetToData;
} RESOURCE_ENTRY;

typedef struct {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
} RESOURCE_DATA;

/* ICO structures */
typedef struct {
    uint8_t  bWidth;
    uint8_t  bHeight;
    uint8_t  bColorCount;
    uint8_t  bReserved;
    uint16_t wPlanes;
    uint16_t wBitCount;
    uint32_t dwBytesInRes;
    uint16_t nID;
} GRPICONDIRENTRY;

typedef struct {
    uint16_t idReserved;
    uint16_t idType;
    uint16_t idCount;
    GRPICONDIRENTRY idEntries[1]; /* Variable length */
} GRPICONDIR;

typedef struct {
    uint8_t  bWidth;
    uint8_t  bHeight;
    uint8_t  bColorCount;
    uint8_t  bReserved;
    uint16_t wPlanes;
    uint16_t wBitCount;
    uint32_t dwBytesInRes;
    uint32_t dwImageOffset;
} ICONDIRENTRY;

#pragma pack(pop)

#define RT_ICON       3
#define RT_GROUP_ICON 14

static FILE *g_file;
static uint8_t *g_rsrc_data;
static uint32_t g_rsrc_rva;
static uint32_t g_rsrc_size;

static uint32_t rva_to_offset(SECTION_HEADER *sections, int num_sections, uint32_t rva)
{
    for (int i = 0; i < num_sections; i++) {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].SizeOfRawData) {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }
    return 0;
}

static void *get_resource_data(uint32_t rva, uint32_t *size, RESOURCE_DATA *data_entry)
{
    uint32_t offset = rva - g_rsrc_rva;
    if (offset >= g_rsrc_size) return NULL;

    *size = data_entry->Size;
    return g_rsrc_data + (data_entry->OffsetToData - g_rsrc_rva);
}

static RESOURCE_ENTRY *find_resource_by_id(RESOURCE_DIR *dir, uint32_t id)
{
    RESOURCE_ENTRY *entries = (RESOURCE_ENTRY*)(dir + 1);
    int total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;

    for (int i = dir->NumberOfNamedEntries; i < total; i++) {
        if (!(entries[i].NameOrId & 0x80000000) && entries[i].NameOrId == id)
            return &entries[i];
    }
    return NULL;
}

static RESOURCE_ENTRY *get_first_resource(RESOURCE_DIR *dir)
{
    RESOURCE_ENTRY *entries = (RESOURCE_ENTRY*)(dir + 1);
    if (dir->NumberOfNamedEntries + dir->NumberOfIdEntries > 0)
        return &entries[0];
    return NULL;
}

int main(int argc, char **argv)
{
    DOS_HEADER dos;
    PE_HEADER pe;
    OPTIONAL_HEADER32 opt;
    SECTION_HEADER *sections = NULL;
    DATA_DIRECTORY rsrc_dir;
    int num_sections;
    int is_pe32plus = 0;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input.exe> <output.ico>\n", argv[0]);
        return 1;
    }

    g_file = fopen(argv[1], "rb");
    if (!g_file) {
        fprintf(stderr, "Error: Cannot open %s\n", argv[1]);
        return 1;
    }

    /* Read DOS header */
    if (fread(&dos, sizeof(dos), 1, g_file) != 1 || dos.e_magic != 0x5A4D) {
        fprintf(stderr, "Error: Not a valid PE file (invalid DOS header)\n");
        fclose(g_file);
        return 1;
    }

    /* Read PE header */
    fseek(g_file, dos.e_lfanew, SEEK_SET);
    if (fread(&pe, sizeof(pe), 1, g_file) != 1 || pe.Signature != 0x4550) {
        fprintf(stderr, "Error: Not a valid PE file (invalid PE signature)\n");
        fclose(g_file);
        return 1;
    }

    num_sections = pe.NumberOfSections;

    /* Read optional header */
    if (fread(&opt, sizeof(opt), 1, g_file) != 1) {
        fprintf(stderr, "Error: Cannot read optional header\n");
        fclose(g_file);
        return 1;
    }

    is_pe32plus = (opt.Magic == 0x20b);

    /* Skip to data directories and find resource directory */
    if (is_pe32plus) {
        /* PE32+ has different optional header layout */
        fseek(g_file, dos.e_lfanew + sizeof(pe) + 112, SEEK_SET); /* Skip to data dirs */
    } else {
        fseek(g_file, dos.e_lfanew + sizeof(pe) + 96, SEEK_SET);
    }

    /* Skip first 2 directories (export, import), read resource directory */
    fseek(g_file, 8 * 2, SEEK_CUR); /* Skip export and import */
    if (fread(&rsrc_dir, sizeof(rsrc_dir), 1, g_file) != 1) {
        fprintf(stderr, "Error: Cannot read resource directory\n");
        fclose(g_file);
        return 1;
    }

    if (rsrc_dir.VirtualAddress == 0 || rsrc_dir.Size == 0) {
        fprintf(stderr, "Error: No resources in this PE file\n");
        fclose(g_file);
        return 1;
    }

    /* Read section headers */
    fseek(g_file, dos.e_lfanew + sizeof(pe) + pe.SizeOfOptionalHeader, SEEK_SET);
    sections = malloc(sizeof(SECTION_HEADER) * num_sections);
    if (fread(sections, sizeof(SECTION_HEADER), num_sections, g_file) != num_sections) {
        fprintf(stderr, "Error: Cannot read section headers\n");
        free(sections);
        fclose(g_file);
        return 1;
    }

    /* Find and load .rsrc section */
    uint32_t rsrc_offset = rva_to_offset(sections, num_sections, rsrc_dir.VirtualAddress);
    if (!rsrc_offset) {
        fprintf(stderr, "Error: Cannot find resource section\n");
        free(sections);
        fclose(g_file);
        return 1;
    }

    g_rsrc_rva = rsrc_dir.VirtualAddress;
    g_rsrc_size = rsrc_dir.Size;
    g_rsrc_data = malloc(g_rsrc_size);

    fseek(g_file, rsrc_offset, SEEK_SET);
    if (fread(g_rsrc_data, 1, g_rsrc_size, g_file) != g_rsrc_size) {
        fprintf(stderr, "Error: Cannot read resource data\n");
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    /* Navigate resource tree: Type -> Name -> Language */
    RESOURCE_DIR *root = (RESOURCE_DIR*)g_rsrc_data;
    RESOURCE_ENTRY *icon_group_type = find_resource_by_id(root, RT_GROUP_ICON);

    if (!icon_group_type) {
        fprintf(stderr, "Error: No icon group found\n");
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    /* Get first icon group */
    RESOURCE_DIR *icon_group_dir = (RESOURCE_DIR*)(g_rsrc_data + (icon_group_type->OffsetToData & 0x7FFFFFFF));
    RESOURCE_ENTRY *first_group = get_first_resource(icon_group_dir);
    if (!first_group) {
        fprintf(stderr, "Error: No icon group entries\n");
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    /* Get language entry */
    RESOURCE_DIR *lang_dir = (RESOURCE_DIR*)(g_rsrc_data + (first_group->OffsetToData & 0x7FFFFFFF));
    RESOURCE_ENTRY *lang_entry = get_first_resource(lang_dir);
    if (!lang_entry) {
        fprintf(stderr, "Error: No language entry\n");
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    /* Get the actual data */
    RESOURCE_DATA *grp_data = (RESOURCE_DATA*)(g_rsrc_data + lang_entry->OffsetToData);
    GRPICONDIR *icon_dir = (GRPICONDIR*)(g_rsrc_data + (grp_data->OffsetToData - g_rsrc_rva));

    printf("Found %d icon(s)\n", icon_dir->idCount);

    /* Find best icon (largest) */
    int best_idx = 0;
    int best_size = 0;
    for (int i = 0; i < icon_dir->idCount; i++) {
        int w = icon_dir->idEntries[i].bWidth ? icon_dir->idEntries[i].bWidth : 256;
        int h = icon_dir->idEntries[i].bHeight ? icon_dir->idEntries[i].bHeight : 256;
        if (w * h > best_size) {
            best_size = w * h;
            best_idx = i;
        }
    }

    printf("Best icon: %dx%d\n",
           icon_dir->idEntries[best_idx].bWidth ? icon_dir->idEntries[best_idx].bWidth : 256,
           icon_dir->idEntries[best_idx].bHeight ? icon_dir->idEntries[best_idx].bHeight : 256);

    /* Find RT_ICON resource with matching ID */
    RESOURCE_ENTRY *icon_type = find_resource_by_id(root, RT_ICON);
    if (!icon_type) {
        fprintf(stderr, "Error: No icon resources\n");
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    RESOURCE_DIR *icon_dir2 = (RESOURCE_DIR*)(g_rsrc_data + (icon_type->OffsetToData & 0x7FFFFFFF));
    RESOURCE_ENTRY *icon_entry = find_resource_by_id(icon_dir2, icon_dir->idEntries[best_idx].nID);

    if (!icon_entry) {
        fprintf(stderr, "Error: Cannot find icon with ID %d\n", icon_dir->idEntries[best_idx].nID);
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    RESOURCE_DIR *icon_lang_dir = (RESOURCE_DIR*)(g_rsrc_data + (icon_entry->OffsetToData & 0x7FFFFFFF));
    RESOURCE_ENTRY *icon_lang = get_first_resource(icon_lang_dir);
    RESOURCE_DATA *icon_data = (RESOURCE_DATA*)(g_rsrc_data + icon_lang->OffsetToData);

    uint8_t *icon_bits = g_rsrc_data + (icon_data->OffsetToData - g_rsrc_rva);
    uint32_t icon_size = icon_data->Size;

    /* Check if icon data is already PNG (magic: 0x89 PNG) */
    static const uint8_t png_magic[] = { 0x89, 0x50, 0x4E, 0x47 };
    int is_png = (icon_size >= 4 && memcmp(icon_bits, png_magic, 4) == 0);

    FILE *outfile = fopen(argv[2], "wb");
    if (!outfile) {
        fprintf(stderr, "Error: Cannot create %s\n", argv[2]);
        free(g_rsrc_data);
        free(sections);
        fclose(g_file);
        return 1;
    }

    if (is_png) {
        /* Icon is already PNG - write directly */
        fwrite(icon_bits, 1, icon_size, outfile);
        fclose(outfile);
        printf("PNG icon saved to %s\n", argv[2]);
    } else {
        /* Icon is BMP/DIB format - wrap in ICO */
        /* ICO header */
        uint16_t ico_reserved = 0, ico_type = 1, ico_count = 1;
        fwrite(&ico_reserved, 2, 1, outfile);
        fwrite(&ico_type, 2, 1, outfile);
        fwrite(&ico_count, 2, 1, outfile);

        /* ICO directory entry */
        ICONDIRENTRY ico_entry = {
            .bWidth = icon_dir->idEntries[best_idx].bWidth,
            .bHeight = icon_dir->idEntries[best_idx].bHeight,
            .bColorCount = icon_dir->idEntries[best_idx].bColorCount,
            .bReserved = 0,
            .wPlanes = icon_dir->idEntries[best_idx].wPlanes,
            .wBitCount = icon_dir->idEntries[best_idx].wBitCount,
            .dwBytesInRes = icon_size,
            .dwImageOffset = 6 + sizeof(ICONDIRENTRY)
        };
        fwrite(&ico_entry, sizeof(ico_entry), 1, outfile);

        /* Icon data */
        fwrite(icon_bits, 1, icon_size, outfile);
        fclose(outfile);
        printf("ICO icon saved to %s (BMP format, use sips to convert)\n", argv[2]);
    }

    free(g_rsrc_data);
    free(sections);
    fclose(g_file);

    return 0;
}
