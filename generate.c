#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utarray.h"

#define BPF_PSEUDO_MAP_FD 1
#define MAPS_SECTION "maps"
#define LICENSE_SECTION "license"

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

struct bpf_insn {
  uint8_t code;
  uint8_t dst_reg : 4;
  uint8_t src_reg : 4;
  int16_t off;
  int32_t imm;
};

struct map_relocation {
  unsigned int insn_offset;
  char* map_name;
};

int replacechar(char* str, char orig, char rep) {
  char* ix = str;
  int n = 0;
  while ((ix = strchr(ix, orig)) != NULL) {
    *ix++ = rep;
    n++;
  }
  return n;
}

void* read_section(Elf64_Shdr* section_header, FILE* f) {
  void* dest = malloc(sizeof(char) * section_header->sh_size);
  fseek(f, section_header->sh_offset, SEEK_SET);
  fread(dest, section_header->sh_size, 1, f);
  return dest;
}

void print_program(char* program_name, void* buf, int buf_size,
                   struct map_relocation* offsets, int of_size) {
  char* header_template_1 = "union bpf_attr* prog_%s(";
  char* header_template_2 =
      ""
      "char* license, char* log_buf, int log_buf_size, int log_level) {\n"
      "	struct bpf_insn* program = calloc(%lu, sizeof(struct bpf_insn));\n";
  char* instruction_template =
      ""
      "	program[%lu] = BPF_INSN(0x%02x, %u, %u, %d, %d);\n";
  char* instruction_rewritten_template =
      ""
      "	program[%lu] = BPF_INSN(0x%02x, %u, %u, %d, fd_%s);\n";
  char* footer_template =
      ""
      "        union bpf_attr* ret = calloc(1, sizeof(union bpf_attr));\n"
      "        ret->prog_type = BPF_PROG_TYPE_KPROBE;\n"
      "        ret->insns = (unsigned long) program;\n"
      "        ret->insn_cnt = %lu;\n"
      "        ret->log_buf = (unsigned long) log_buf;\n"
      "        ret->log_size = log_buf_size;\n"
      "        ret->log_level = log_level;\n"
      "        ret->license = (unsigned long) license;\n"
      "        return ret;\n"
      "}\n";

  replacechar(program_name, '/', '_');
  printf(header_template_1, program_name);

  UT_array* maps_unique;
  utarray_new(maps_unique, &ut_str_icd);

  bool printed = false;
  struct map_relocation* off = offsets;
  for (int p = 0; p < of_size; p++) {
    bool saw_before = false;
    char** previous_map = NULL;
    while (previous_map = (char**)utarray_next(maps_unique, previous_map)) {
      if (strcmp(off->map_name, *previous_map) == 0) {
        saw_before = true;
        break;
      }
    }
    if (saw_before) {
      off++;
      continue;
    }
    if (printed) {
      printf(", ");
    }
    printf("int fd_%s", off->map_name);
    printed = true;
    utarray_push_back(maps_unique, &(off->map_name));
    off++;
  }
  if (of_size != 0) {
    printf(", ");
  }

  struct bpf_insn* insn = buf;
  unsigned int num_insns = buf_size / sizeof(struct bpf_insn);
  printf(header_template_2, num_insns);

  for (unsigned int i = 0; i < num_insns; i++) {
    bool is_rewritten = false;
    struct map_relocation* offset = offsets;
    for (int o = 0; o < of_size; o++) {
      if (offset->insn_offset / 8 == i) {
        is_rewritten = true;
        printf(instruction_rewritten_template, i, insn->code, insn->dst_reg,
               BPF_PSEUDO_MAP_FD, insn->off, offset->map_name);
        break;
      }
      offset++;
    }
    if (!is_rewritten) {
      printf(instruction_template, i, insn->code, insn->dst_reg, insn->src_reg,
             insn->off, insn->imm);
    }
    insn++;
  }
  printf(footer_template, num_insns);
}

void print_header() {
  printf(
      ""
      "#include <stdlib.h>\n"
      "#include <linux/bpf_common.h>\n"
      "#include <linux/bpf.h>\n"
      "\n"
      "#define BPF_INSN(OPCODE, DESTINATION, SOURCE, OFFSET, IMMEDIATE)\\\n"
      "	((struct bpf_insn) {\\\n"
      "		.code  = OPCODE,\\\n"
      "		.dst_reg = DESTINATION,\\\n"
      "		.src_reg = SOURCE,\\\n"
      "		.off   = OFFSET,\\\n"
      "		.imm   = IMMEDIATE })\n\n");
}

void print_map(void* maps, char* map_name, int map_offset) {
  char* map_template =
      "\n"
      "union bpf_attr map_%s = {\n"
      "	.map_type = %u,\n"
      "	.key_size = %u,\n"
      "	.value_size = %u,\n"
      "	.max_entries = %u,\n"
      "	.map_flags = 0,\n"
      "};\n";
  struct bpf_map_def* map = ((void*)maps) + map_offset;
  printf(map_template, map_name, map->type, map->key_size, map->value_size,
         map->max_entries);
}

void print_maps(char** map_name_by_offset, int num_maps,
                Elf64_Shdr* maps_section, FILE* f) {
  void* maps = NULL;
  for (int map_offset = 0; map_offset < num_maps; map_offset++) {
    char* map_name = map_name_by_offset[map_offset];
    if (map_name != NULL) {
      if (maps == NULL) {
        maps = read_section(maps_section, f);
      }
      print_map(maps, map_name, map_offset);
    }
  }
}

int find_relocation_section_index(Elf64_Shdr* sections, void* string_table,
                                  int num_sections,
                                  char* program_section_name) {
  char relocation_name[4 + strlen(program_section_name)];
  relocation_name[0] = '\0';
  strcat(relocation_name, ".rel");
  strcat(relocation_name, program_section_name);

  Elf64_Shdr* sec = sections;
  for (int s = 0; s < num_sections; s++) {
    char* name = ((char*)string_table) + sections->sh_name;
    if (strcmp(name, relocation_name) == 0) {
      return s;
    }
    sections++;
  }
  return -1;
}

Elf64_Sym* get_symbol(Elf64_Shdr* sections, void* string_table,
                      int num_sections, FILE* f, uint32_t symbol_name) {
  Elf64_Shdr* sec = sections;
  for (int s = 0; s < num_sections; s++) {
    char* name = ((char*)string_table) + sec->sh_name;
    if (strcmp(name, ".symtab") == 0) {
      Elf64_Sym* sym_table = (Elf64_Sym*)read_section(sec, f);
      Elf64_Sym* sym = sym_table + symbol_name;
      if (symbol_name > sec->sh_size / sizeof(Elf64_Sym) - 1) {
        return NULL;
      }
      return sym;
    }
    sec++;
  }
  return NULL;
}

int find_section_index(void* string_table, void* section_header_buf,
                       int num_sections, char* name) {
  Elf64_Shdr* section_header = section_header_buf;
  for (int s = 0; s < num_sections; s++) {
    char* section_name = ((char*)string_table) + section_header->sh_name;
    if (strcmp(name, section_name) == 0) {
      return s;
    }
    section_header++;
  }
  return -1;
}

int main(int argc, char* argv[]) {
  if (argc == 1) {
    fprintf(stderr, "Usage: %s path/to/bpf_elf.o\n", argv[0]);
    return 1;
  }

  char* object_file = argv[1];
  FILE* f = fopen(object_file, "r");
  if (f == NULL) {
    fprintf(stderr, "ERROR: unable to read %s (error number: %d)\n",
            object_file, errno);
    return 1;
  }

  char ident[EI_NIDENT];
  fread(ident, EI_NIDENT, 1, f);
  rewind(f);
  if (ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "ERROR: the referenced binary was not 64-bit ELF\n");
    return 1;
  }

  char hdr_buf[sizeof(Elf64_Ehdr)];
  fread(hdr_buf, sizeof(Elf64_Ehdr), 1, f);
  Elf64_Ehdr* hdr = (Elf64_Ehdr*)hdr_buf;
  if (hdr->e_machine != EM_BPF) {
    fprintf(stderr,
            "ERROR: the object does not appear to contain BPF bytecode\n");
    return 1;
  }

  uint64_t section_header_offset = hdr->e_shoff;
  if (section_header_offset == 0 || hdr->e_shnum == 0) {
    fprintf(stderr, "ERROR: unable to find the ELF section header\n");
    return 1;
  }
  fseek(f, section_header_offset, SEEK_SET);

  uint64_t string_table_idx = hdr->e_shstrndx;
  if (string_table_idx == SHN_UNDEF || hdr->e_shnum < string_table_idx + 1) {
    fprintf(stderr, "ERROR: unable to find the string table ELF section\n");
    return 1;
  }

  char shdr_buf[hdr->e_shentsize * hdr->e_shnum];
  fread(shdr_buf, hdr->e_shentsize, hdr->e_shnum, f);

  Elf64_Shdr* string_table_header = ((Elf64_Shdr*)&shdr_buf) + string_table_idx;
  void* string_table = read_section(string_table_header, f);

  int maps_index =
      find_section_index(string_table, shdr_buf, hdr->e_shnum, MAPS_SECTION);
  Elf64_Shdr* maps_section =
      (maps_index == -1) ? NULL : ((Elf64_Shdr*)&shdr_buf) + maps_index;
  char*
      map_name_by_map_offset[maps_section == NULL ? 0 : maps_section->sh_size];
  memset(map_name_by_map_offset, 0, sizeof(map_name_by_map_offset));

  print_header();

  Elf64_Shdr* shdr = (Elf64_Shdr*)&shdr_buf;
  for (int s = 0; s < hdr->e_shnum; s++) {
    char* name = ((char*)string_table) + shdr->sh_name;

    if (shdr->sh_type == SHT_PROGBITS && name[0] != '.' &&
        strcmp(MAPS_SECTION, name) != 0 && strcmp(LICENSE_SECTION, name) != 0) {
      void* program = read_section(shdr, f);

      int relocation_idx = find_relocation_section_index(
          (Elf64_Shdr*)shdr_buf, string_table, hdr->e_shnum, name);
      if (relocation_idx == -1) {
        print_program(name, program, shdr->sh_size, NULL, 0);
      } else {
        Elf64_Shdr* relocation_section =
            ((Elf64_Shdr*)&shdr_buf) + relocation_idx;
        int num_relocations = relocation_section->sh_size / sizeof(Elf64_Rel);
        struct map_relocation offsets[num_relocations];

        Elf64_Rel* relocation = (Elf64_Rel*)read_section(relocation_section, f);
        for (int r = 0; r < num_relocations; r++) {
          uint32_t symbol_name = ELF64_R_SYM(relocation->r_info);
          Elf64_Sym* sym = get_symbol((Elf64_Shdr*)&shdr_buf, string_table,
                                      hdr->e_shnum, f, symbol_name);
          offsets[r].insn_offset = relocation->r_offset;
          offsets[r].map_name = ((char*)string_table) + sym->st_name;

          map_name_by_map_offset[sym->st_value] =
              ((char*)string_table) + sym->st_name;
          relocation++;
        }
        print_program(name, program, shdr->sh_size, offsets, num_relocations);
      }
    }
    shdr++;
  }
  int num_maps = sizeof(map_name_by_map_offset) / sizeof(char*);
  print_maps(map_name_by_map_offset, num_maps, maps_section, f);

  fclose(f);
  return 0;
}
