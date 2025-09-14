/* CRIS-specific support for 32-bit ELF.
   Copyright (C) 2000-2025 Free Software Foundation, Inc.
   Contributed by Axis Communications AB.
   Written by Hans-Peter Nilsson, based on elf32-fr30.c
   PIC and shlib bits based primarily on elf32-m68k.c and elf32-i386.c.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/cris.h"
#include <limits.h>

bfd_reloc_status_type
cris_elf_pcrel_reloc (bfd *, arelent *, asymbol *, void *,
		      asection *, bfd *, char **);
static bool
cris_elf_set_mach_from_flags (bfd *, unsigned long);

/* Forward declarations.  */
static reloc_howto_type cris_elf_howto_table [] =
{
  /* This reloc does nothing.  */
  HOWTO (R_CRIS_NONE,		/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_NONE",		/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* An 8 bit absolute relocation.  */
  HOWTO (R_CRIS_8,		/* type */
	 0,			/* rightshift */
	 1,			/* size */
	 8,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_8",		/* name */
	 false,			/* partial_inplace */
	 0x0000,		/* src_mask */
	 0x00ff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 16 bit absolute relocation.  */
  HOWTO (R_CRIS_16,		/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_16",		/* name */
	 false,			/* partial_inplace */
	 0x00000000,		/* src_mask */
	 0x0000ffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 32 bit absolute relocation.  */
  HOWTO (R_CRIS_32,		/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 /* We don't want overflow complaints for 64-bit vma builds
	    for e.g. sym+0x40000000 (or actually sym-0xc0000000 in
	    32-bit ELF) where sym=0xc0001234.
	    Don't do this for the PIC relocs, as we don't expect to
	    see them with large offsets.  */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_32",		/* name */
	 false,			/* partial_inplace */
	 0x00000000,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* An 8 bit PC-relative relocation.  */
  HOWTO (R_CRIS_8_PCREL,	/* type */
	 0,			/* rightshift */
	 1,			/* size */
	 8,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 cris_elf_pcrel_reloc,	/* special_function */
	 "R_CRIS_8_PCREL",	/* name */
	 false,			/* partial_inplace */
	 0x0000,		/* src_mask */
	 0x00ff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* A 16 bit PC-relative relocation.  */
  HOWTO (R_CRIS_16_PCREL,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 cris_elf_pcrel_reloc,	/* special_function */
	 "R_CRIS_16_PCREL",	/* name */
	 false,			/* partial_inplace */
	 0x00000000,		/* src_mask */
	 0x0000ffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* A 32 bit PC-relative relocation.  */
  HOWTO (R_CRIS_32_PCREL,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 cris_elf_pcrel_reloc,	/* special_function */
	 "R_CRIS_32_PCREL",	/* name */
	 false,			/* partial_inplace */
	 0x00000000,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* GNU extension to record C++ vtable hierarchy.  */
  HOWTO (R_CRIS_GNU_VTINHERIT,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 NULL,			/* special_function */
	 "R_CRIS_GNU_VTINHERIT", /* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* GNU extension to record C++ vtable member usage.  */
  HOWTO (R_CRIS_GNU_VTENTRY,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 _bfd_elf_rel_vtable_reloc_fn,	/* special_function */
	 "R_CRIS_GNU_VTENTRY",	 /* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* This is used only by the dynamic linker.  The symbol should exist
     both in the object being run and in some shared library.  The
     dynamic linker copies the data addressed by the symbol from the
     shared library into the object, because the object being
     run has to have the data at some particular address.  */
  HOWTO (R_CRIS_COPY,		/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_COPY",		/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Like R_CRIS_32, but used when setting global offset table entries.  */
  HOWTO (R_CRIS_GLOB_DAT,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_GLOB_DAT",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Marks a procedure linkage table entry for a symbol.  */
  HOWTO (R_CRIS_JUMP_SLOT,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_JUMP_SLOT",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Used only by the dynamic linker.  When the object is run, this
     longword is set to the load address of the object, plus the
     addend.  */
  HOWTO (R_CRIS_RELATIVE,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_RELATIVE",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Like R_CRIS_32, but referring to the GOT table entry for the symbol.  */
  HOWTO (R_CRIS_16_GOT,		/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_16_GOT",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_CRIS_32_GOT,		/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_32_GOT",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Like R_CRIS_32_GOT, but referring to (and requesting a) PLT part of
     the GOT table for the symbol.  */
  HOWTO (R_CRIS_16_GOTPLT,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_16_GOTPLT",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_CRIS_32_GOTPLT,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_32_GOTPLT",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 32-bit offset from GOT to (local const) symbol: no GOT entry should
     be necessary.  */
  HOWTO (R_CRIS_32_GOTREL,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_32_GOTREL",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 32-bit offset from GOT to entry for this symbol in PLT and request
     to create PLT entry for symbol.  */
  HOWTO (R_CRIS_32_PLT_GOTREL,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_CRIS_32_PLT_GOTREL", /* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* A 32-bit offset from PC (location after the relocation) + addend to
     entry for this symbol in PLT and request to create PLT entry for
     symbol.  */
  HOWTO (R_CRIS_32_PLT_PCREL,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 cris_elf_pcrel_reloc,	/* special_function */
	 "R_CRIS_32_PLT_PCREL",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* We don't handle these in any special manner and cross-format
     linking is not supported; just recognize them enough to pass them
     around.  FIXME: do the same for most PIC relocs and add sanity
     tests to actually refuse gracefully to handle these and PIC
     relocs for cross-format linking.  */
#define TLSHOWTO32(name) \
 HOWTO (name, 0, 4, 32, false, 0, complain_overflow_bitfield, \
	bfd_elf_generic_reloc, #name, false, 0, 0xffffffff, false)
#define TLSHOWTO16X(name, X)	     \
 HOWTO (name, 0, 2, 16, false, 0, complain_overflow_ ## X, \
	bfd_elf_generic_reloc, #name, false, 0, 0xffff, false)
#define TLSHOWTO16(name) TLSHOWTO16X(name, unsigned)
#define TLSHOWTO16S(name) TLSHOWTO16X(name, signed)

  TLSHOWTO32 (R_CRIS_32_GOT_GD),
  TLSHOWTO16 (R_CRIS_16_GOT_GD),
  TLSHOWTO32 (R_CRIS_32_GD),
  TLSHOWTO32 (R_CRIS_DTP),
  TLSHOWTO32 (R_CRIS_32_DTPREL),
  TLSHOWTO16S (R_CRIS_16_DTPREL),
  TLSHOWTO32 (R_CRIS_32_GOT_TPREL),
  TLSHOWTO16S (R_CRIS_16_GOT_TPREL),
  TLSHOWTO32 (R_CRIS_32_TPREL),
  TLSHOWTO16S (R_CRIS_16_TPREL),
  TLSHOWTO32 (R_CRIS_DTPMOD),
  TLSHOWTO32 (R_CRIS_32_IE)
};

/* Map BFD reloc types to CRIS ELF reloc types.  */

struct cris_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned int cris_reloc_val;
};

static const struct cris_reloc_map cris_reloc_map [] =
{
  { BFD_RELOC_NONE,		R_CRIS_NONE },
  { BFD_RELOC_8,		R_CRIS_8 },
  { BFD_RELOC_16,		R_CRIS_16 },
  { BFD_RELOC_32,		R_CRIS_32 },
  { BFD_RELOC_8_PCREL,		R_CRIS_8_PCREL },
  { BFD_RELOC_16_PCREL,		R_CRIS_16_PCREL },
  { BFD_RELOC_32_PCREL,		R_CRIS_32_PCREL },
  { BFD_RELOC_VTABLE_INHERIT,	R_CRIS_GNU_VTINHERIT },
  { BFD_RELOC_VTABLE_ENTRY,	R_CRIS_GNU_VTENTRY },
  { BFD_RELOC_CRIS_COPY,	R_CRIS_COPY },
  { BFD_RELOC_CRIS_GLOB_DAT,	R_CRIS_GLOB_DAT },
  { BFD_RELOC_CRIS_JUMP_SLOT,	R_CRIS_JUMP_SLOT },
  { BFD_RELOC_CRIS_RELATIVE,	R_CRIS_RELATIVE },
  { BFD_RELOC_CRIS_16_GOT,	R_CRIS_16_GOT },
  { BFD_RELOC_CRIS_32_GOT,	R_CRIS_32_GOT },
  { BFD_RELOC_CRIS_16_GOTPLT,	R_CRIS_16_GOTPLT },
  { BFD_RELOC_CRIS_32_GOTPLT,	R_CRIS_32_GOTPLT },
  { BFD_RELOC_CRIS_32_GOTREL,	R_CRIS_32_GOTREL },
  { BFD_RELOC_CRIS_32_PLT_GOTREL, R_CRIS_32_PLT_GOTREL },
  { BFD_RELOC_CRIS_32_PLT_PCREL, R_CRIS_32_PLT_PCREL },
  { BFD_RELOC_CRIS_32_GOT_GD,	R_CRIS_32_GOT_GD },
  { BFD_RELOC_CRIS_16_GOT_GD,	R_CRIS_16_GOT_GD },
  { BFD_RELOC_CRIS_32_GD,	R_CRIS_32_GD },
  { BFD_RELOC_CRIS_DTP,	R_CRIS_DTP },
  { BFD_RELOC_CRIS_32_DTPREL,	R_CRIS_32_DTPREL },
  { BFD_RELOC_CRIS_16_DTPREL,	R_CRIS_16_DTPREL },
  { BFD_RELOC_CRIS_32_GOT_TPREL, R_CRIS_32_GOT_TPREL },
  { BFD_RELOC_CRIS_16_GOT_TPREL, R_CRIS_16_GOT_TPREL },
  { BFD_RELOC_CRIS_32_TPREL,	R_CRIS_32_TPREL },
  { BFD_RELOC_CRIS_16_TPREL,	R_CRIS_16_TPREL },
  { BFD_RELOC_CRIS_DTPMOD,	R_CRIS_DTPMOD },
  { BFD_RELOC_CRIS_32_IE,	R_CRIS_32_IE }
};

static reloc_howto_type *cris_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code)
{
    size_t map_size = sizeof(cris_reloc_map) / sizeof(cris_reloc_map[0]);
    size_t i;

    for (i = 0; i < map_size; ++i) {
        if (cris_reloc_map[i].bfd_reloc_val == code) {
            unsigned int cris_val = cris_reloc_map[i].cris_reloc_val;
            if (cris_val < sizeof(cris_elf_howto_table) / sizeof(cris_elf_howto_table[0])) {
                return &cris_elf_howto_table[cris_val];
            }
            return NULL;
        }
    }
    return NULL;
}

static reloc_howto_type *cris_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED, const char *r_name) {
    if (r_name == NULL) {
        return NULL;
    }
    size_t table_size = sizeof(cris_elf_howto_table) / sizeof(cris_elf_howto_table[0]);
    for (size_t i = 0; i < table_size; ++i) {
        const char *name = cris_elf_howto_table[i].name;
        if (name && strcasecmp(name, r_name) == 0) {
            return &cris_elf_howto_table[i];
        }
    }
    return NULL;
}

/* Set the howto pointer for an CRIS ELF reloc.  */

static bool cris_info_to_howto_rela(bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr, Elf_Internal_Rela *dst) {
    enum elf_cris_reloc_type r_type = ELF32_R_TYPE(dst->r_info);

    if (r_type < 0 || r_type >= R_CRIS_max) {
        _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, r_type);
        bfd_set_error(bfd_error_bad_value);
        return false;
    }

    cache_ptr->howto = &cris_elf_howto_table[r_type];
    return true;
}

bfd_reloc_status_type cris_elf_pcrel_reloc(
    bfd *abfd,
    arelent *reloc_entry,
    asymbol *symbol,
    void *data,
    asection *input_section,
    bfd *output_bfd,
    char **error_message)
{
    if (output_bfd == NULL) {
        unsigned int reloc_size = bfd_get_reloc_size(reloc_entry->howto);
        if (reloc_entry->addend < (bfd_vma)reloc_size) {
            if (error_message != NULL)
                *error_message = "Relocation addend underrun";
            return bfd_reloc_outofrange;
        }
        reloc_entry->addend -= reloc_size;
    }

    return bfd_elf_generic_reloc(
        abfd,
        reloc_entry,
        symbol,
        data,
        input_section,
        output_bfd,
        error_message
    );
}

/* Support for core dump NOTE sections.
   The slightly unintuitive code layout is an attempt to keep at least
   some similarities with other ports, hoping to simplify general
   changes, while still keeping Linux/CRIS and Linux/CRISv32 code apart.  */

static bool cris_elf_grok_prstatus(bfd *abfd, Elf_Internal_Note *note)
{
    int offset = 0;
    size_t size = 0;
    unsigned int mach = bfd_get_mach(abfd);

    if (note == NULL || abfd == NULL || note->descdata == NULL)
        return false;

    if (mach == bfd_mach_cris_v32) {
        if (note->descsz != 202)
            return false;

        elf_tdata(abfd)->core->signal = bfd_get_16(abfd, note->descdata + 12);
        elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, note->descdata + 22);
        offset = 70;
        size = 128;
    } else {
        if (note->descsz != 214)
            return false;

        elf_tdata(abfd)->core->signal = bfd_get_16(abfd, note->descdata + 12);
        elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, note->descdata + 22);
        offset = 70;
        size = 140;
    }

    return _bfd_elfcore_make_pseudosection(abfd, ".reg", size, note->descpos + offset);
}

static bool cris_elf_grok_psinfo(bfd *abfd, Elf_Internal_Note *note)
{
    bool is_v32 = (bfd_get_mach(abfd) == bfd_mach_cris_v32);

    if (note->descsz != 124)
        return false;

    char *program = _bfd_elfcore_strndup(abfd, note->descdata + 28, 16);
    char *command = _bfd_elfcore_strndup(abfd, note->descdata + 44, 80);

    if (!program || !command) {
        free(program);
        free(command);
        return false;
    }

    elf_tdata(abfd)->core->program = program;
    elf_tdata(abfd)->core->command = command;

    size_t n = strlen(command);
    if (n > 0 && command[n - 1] == ' ')
        command[n - 1] = '\0';

    return true;
}

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF_DYNAMIC_INTERPRETER "/lib/ld.so.1"

/* The size in bytes of an entry in the procedure linkage table.  */

#define PLT_ENTRY_SIZE 20
#define PLT_ENTRY_SIZE_V32 26

/* The first entry in an absolute procedure linkage table looks like this.  */

static const bfd_byte elf_cris_plt0_entry[PLT_ENTRY_SIZE] =
{
  0xfc, 0xe1,
  0x7e, 0x7e,	/* push mof.  */
  0x7f, 0x0d,   /*  (dip [pc+]) */
  0, 0, 0, 0,	/*  Replaced with address of .got + 4.  */
  0x30, 0x7a,	/* move [...],mof */
  0x7f, 0x0d,   /*  (dip [pc+]) */
  0, 0, 0, 0,	/*  Replaced with address of .got + 8.  */
  0x30, 0x09	/* jump [...] */
};

static const bfd_byte elf_cris_plt0_entry_v32[PLT_ENTRY_SIZE_V32] =
{
  0x84, 0xe2,	/* subq 4,$sp */
  0x6f, 0xfe,	/* move.d 0,$acr */
  0, 0, 0, 0,	/*  Replaced by address of .got + 4.  */
  0x7e, 0x7a,	/* move $mof,[$sp] */
  0x3f, 0x7a,	/* move [$acr],$mof */
  0x04, 0xf2,	/* addq 4,acr */
  0x6f, 0xfa,	/* move.d [$acr],$acr */
  0xbf, 0x09,	/* jump $acr */
  0xb0, 0x05,	/* nop */
  0, 0		/*  Pad out to 26 bytes.  */
};

/* Subsequent entries in an absolute procedure linkage table look like
   this.  */

static const bfd_byte elf_cris_plt_entry[PLT_ENTRY_SIZE] =
{
  0x7f, 0x0d,   /*  (dip [pc+]) */
  0, 0, 0, 0,	/*  Replaced with address of this symbol in .got.  */
  0x30, 0x09,	/* jump [...] */
  0x3f,	 0x7e,	/* move [pc+],mof */
  0, 0, 0, 0,	/*  Replaced with offset into relocation table.  */
  0x2f, 0xfe,	/* add.d [pc+],pc */
  0xec, 0xff,
  0xff, 0xff	/*  Replaced with offset to start of .plt.  */
};

static const bfd_byte elf_cris_plt_entry_v32[PLT_ENTRY_SIZE_V32] =
{
  0x6f, 0xfe,	/* move.d 0,$acr */
  0, 0, 0, 0,	/*  Replaced with address of this symbol in .got.  */
  0x6f, 0xfa,   /* move.d [$acr],$acr */
  0xbf, 0x09,   /* jump $acr */
  0xb0, 0x05,	/* nop */
  0x3f, 0x7e,	/* move 0,mof */
  0, 0, 0, 0,	/*  Replaced with offset into relocation table. */
  0xbf, 0x0e,	/* ba start_of_plt0_entry */
  0, 0, 0, 0,	/*  Replaced with offset to plt0 entry.  */
  0xb0, 0x05	/* nop */
};

/* The first entry in a PIC procedure linkage table looks like this.  */

static const bfd_byte elf_cris_pic_plt0_entry[PLT_ENTRY_SIZE] =
{
  0xfc, 0xe1, 0x7e, 0x7e,	/* push mof */
  0x04, 0x01, 0x30, 0x7a,	/* move [r0+4],mof */
  0x08, 0x01, 0x30, 0x09,	/* jump [r0+8] */
  0, 0, 0, 0, 0, 0, 0, 0,	/*  Pad out to 20 bytes.  */
};

static const bfd_byte elf_cris_pic_plt0_entry_v32[PLT_ENTRY_SIZE_V32] =
{
  0x84, 0xe2,	/* subq 4,$sp */
  0x04, 0x01,	/* addoq 4,$r0,$acr */
  0x7e, 0x7a,	/* move $mof,[$sp] */
  0x3f, 0x7a,	/* move [$acr],$mof */
  0x04, 0xf2,	/* addq 4,$acr */
  0x6f, 0xfa,	/* move.d [$acr],$acr */
  0xbf, 0x09,	/* jump $acr */
  0xb0, 0x05,	/* nop */
  0, 0,		/*  Pad out to 26 bytes.  */
  0, 0, 0, 0,
  0, 0, 0, 0
};

/* Subsequent entries in a PIC procedure linkage table look like this.  */

static const bfd_byte elf_cris_pic_plt_entry[PLT_ENTRY_SIZE] =
{
  0x6f, 0x0d,   /*  (bdap [pc+].d,r0) */
  0, 0, 0, 0,	/*  Replaced with offset of this symbol in .got.  */
  0x30, 0x09,	/* jump [...] */
  0x3f, 0x7e,	/* move [pc+],mof */
  0, 0, 0, 0,	/*  Replaced with offset into relocation table.  */
  0x2f, 0xfe,	/* add.d [pc+],pc */
  0xec, 0xff,	/*  Replaced with offset to start of .plt.  */
  0xff, 0xff
};

static const bfd_byte elf_cris_pic_plt_entry_v32[PLT_ENTRY_SIZE_V32] =
{
  0x6f, 0x0d,	/* addo.d 0,$r0,$acr */
  0, 0, 0, 0,	/*  Replaced with offset of this symbol in .got.  */
  0x6f, 0xfa,	/* move.d [$acr],$acr */
  0xbf, 0x09,	/* jump $acr */
  0xb0, 0x05,	/* nop */
  0x3f, 0x7e,	/* move relocoffs,$mof */
  0, 0, 0, 0,	/*  Replaced with offset into relocation table.  */
  0xbf, 0x0e,	/* ba start_of_plt */
  0, 0, 0, 0,	/*  Replaced with offset to start of .plt.  */
  0xb0, 0x05	/* nop */
};

/* We copy elf32-m68k.c and elf32-i386.c for the basic linker hash bits
   (and most other PIC/shlib stuff).  Check that we don't drift away
   without reason.

   The CRIS linker, like the m68k and i386 linkers (and probably the rest
   too) needs to keep track of the number of relocs that it decides to
   copy in check_relocs for each symbol.  This is so that it can discard
   PC relative relocs if it doesn't need them when linking with
   -Bsymbolic.  We store the information in a field extending the regular
   ELF linker hash table.  */

/* This structure keeps track of the number of PC relative relocs we have
   copied for a given symbol.  */

struct elf_cris_pcrel_relocs_copied
{
  /* Next section.  */
  struct elf_cris_pcrel_relocs_copied *next;

  /* A section in dynobj.  */
  asection *section;

  /* Number of relocs copied in this section.  */
  bfd_size_type count;

  /* Example of reloc being copied, for message.  */
  enum elf_cris_reloc_type r_type;
};

/* CRIS ELF linker hash entry.  */

struct elf_cris_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Number of PC relative relocs copied for this symbol.  */
  struct elf_cris_pcrel_relocs_copied *pcrel_relocs_copied;

  /* The GOTPLT references are CRIS-specific; the goal is to avoid having
     both a general GOT and a PLT-specific GOT entry for the same symbol,
     when it is referenced both as a function and as a function pointer.

     Number of GOTPLT references for a function.  */
  bfd_signed_vma gotplt_refcount;

  /* Actual GOTPLT index for this symbol, if applicable, or zero if not
     (zero is never used as an index).  FIXME: We should be able to fold
     this with gotplt_refcount in a union, like the got and plt unions in
     elf_link_hash_entry.  */
  bfd_size_type gotplt_offset;

  /* The root.got.refcount is the sum of the regular reference counts
     (this) and those members below.  We have to keep a separate count
     to track when we've found the first (or last) reference to a
     regular got entry.  The offset is in root.got.offset.  */
  bfd_signed_vma reg_got_refcount;

  /* Similar to the above, the number of reloc references to this
     symbols that need a R_CRIS_32_TPREL slot.  The offset is in
     root.got.offset, because this and .dtp_refcount can't validly
     happen when there's also a regular GOT entry; that's invalid
     input for which an error is emitted.  */
  bfd_signed_vma tprel_refcount;

  /* Similar to the above, the number of reloc references to this
     symbols that need a R_CRIS_DTP slot.  The offset is in
     root.got.offset; plus 4 if .tprel_refcount > 0.  */
  bfd_signed_vma dtp_refcount;
};

static bool
elf_cris_discard_excess_dso_dynamics (struct elf_cris_link_hash_entry *,
				      void * );
static bool
elf_cris_discard_excess_program_dynamics (struct elf_cris_link_hash_entry *,
					  void *);

/* The local_got_refcounts and local_got_offsets are a multiple of
   LSNUM in size, namely LGOT_ALLOC_NELTS_FOR(LSNUM) (plus one for the
   refcount for GOT itself, see code), with the summary / group offset
   for local symbols located at offset N, reference counts for
   ordinary (address) relocs at offset N + LSNUM, for R_CRIS_DTP
   relocs at offset N + 2*LSNUM, and for R_CRIS_32_TPREL relocs at N +
   3*LSNUM.  */

#define LGOT_REG_NDX(x) ((x) + symtab_hdr->sh_info)
#define LGOT_DTP_NDX(x) ((x) + 2 * symtab_hdr->sh_info)
#define LGOT_TPREL_NDX(x) ((x) + 3 * symtab_hdr->sh_info)
#define LGOT_ALLOC_NELTS_FOR(x) ((x) * 4)

/* CRIS ELF linker hash table.  */

struct elf_cris_link_hash_table
{
  struct elf_link_hash_table root;

  /* We can't use the PLT offset and calculate to get the GOTPLT offset,
     since we try and avoid creating GOTPLT:s when there's already a GOT.
     Instead, we keep and update the next available index here.  */
  bfd_size_type next_gotplt_entry;

  /* The number of R_CRIS_32_DTPREL and R_CRIS_16_DTPREL that have
     been seen for any input; if != 0, then the constant-offset
     R_CRIS_DTPMOD is needed for this DSO/executable.  This turns
     negative at relocation, so that we don't need an extra flag for
     when the reloc is output.  */
  bfd_signed_vma dtpmod_refcount;
};

/* Traverse a CRIS ELF linker hash table.  */

#define elf_cris_link_hash_traverse(table, func, info)			\
  (elf_link_hash_traverse						\
   (&(table)->root,							\
    (bool (*) (struct elf_link_hash_entry *, void *)) (func),		\
    (info)))

/* Get the CRIS ELF linker hash table from a link_info structure.  */

#define elf_cris_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == CRIS_ELF_DATA)		\
   ? (struct elf_cris_link_hash_table *) (p)->hash : NULL)

/* Get the CRIS ELF linker hash entry from a regular hash entry (the
   "parent class").  The .root reference is just a simple type
   check on the argument.  */

#define elf_cris_hash_entry(p) \
 ((struct elf_cris_link_hash_entry *) (&(p)->root))

/* Create an entry in a CRIS ELF linker hash table.  */

static struct bfd_hash_entry *
elf_cris_link_hash_newfunc(struct bfd_hash_entry *entry,
                           struct bfd_hash_table *table,
                           const char *string)
{
    struct elf_cris_link_hash_entry *ret = (struct elf_cris_link_hash_entry *)entry;

    if (!ret)
        ret = (struct elf_cris_link_hash_entry *)bfd_hash_allocate(table, sizeof(struct elf_cris_link_hash_entry));
    if (!ret)
        return NULL;

    ret = (struct elf_cris_link_hash_entry *)_bfd_elf_link_hash_newfunc((struct bfd_hash_entry *)ret, table, string);
    if (!ret)
        return NULL;

    ret->pcrel_relocs_copied = NULL;
    ret->gotplt_refcount = 0;
    ret->gotplt_offset = 0;
    ret->dtp_refcount = 0;
    ret->tprel_refcount = 0;
    ret->reg_got_refcount = 0;

    return (struct bfd_hash_entry *)ret;
}

/* Create a CRIS ELF linker hash table.  */

static struct bfd_link_hash_table *
elf_cris_link_hash_table_create(bfd *abfd)
{
    struct elf_cris_link_hash_table *ret;
    size_t amt = sizeof(struct elf_cris_link_hash_table);

    ret = (struct elf_cris_link_hash_table *)bfd_zmalloc(amt);
    if (ret == NULL)
        return NULL;

    if (!_bfd_elf_link_hash_table_init(
            &ret->root,
            abfd,
            elf_cris_link_hash_newfunc,
            sizeof(struct elf_cris_link_hash_entry)))
    {
        free(ret);
        return NULL;
    }

    ret->next_gotplt_entry = 12;

    return &ret->root.root;
}

/* Perform a single relocation.  By default we use the standard BFD
   routines, with a few tweaks.  */

static bfd_reloc_status_type cris_final_link_relocate(
    reloc_howto_type *howto,
    bfd *input_bfd,
    asection *input_section,
    bfd_byte *contents,
    Elf_Internal_Rela *rel,
    bfd_vma relocation
) {
    enum elf_cris_reloc_type r_type = ELF32_R_TYPE(rel->r_info);

    switch (r_type) {
        case R_CRIS_16_GOTPLT:
        case R_CRIS_16_GOT:
            if ((bfd_signed_vma)relocation < 0) {
                return bfd_reloc_overflow;
            }
            break;

        case R_CRIS_32_PLT_PCREL:
        case R_CRIS_32_PCREL:
            relocation -= 2;
            /* fall through */
        case R_CRIS_8_PCREL:
        case R_CRIS_16_PCREL:
            relocation -= 2;
            break;

        default:
            break;
    }

    return _bfd_final_link_relocate(
        howto,
        input_bfd,
        input_section,
        contents,
        rel->r_offset,
        relocation,
        rel->r_addend
    );
}


/* The number of errors left before we stop outputting reloc-specific
   explanatory messages.  By coincidence, this works nicely together
   with the default number of messages you'll get from LD about
   "relocation truncated to fit" messages before you get an
   "additional relocation overflows omitted from the output".  */
static int additional_relocation_error_msg_count = 10;

/* Relocate an CRIS ELF section.  See elf32-fr30.c, from where this was
   copied, for further comments.  */

static int cris_elf_relocate_section(
    bfd *output_bfd ATTRIBUTE_UNUSED,
    struct bfd_link_info *info,
    bfd *input_bfd,
    asection *input_section,
    bfd_byte *contents,
    Elf_Internal_Rela *relocs,
    Elf_Internal_Sym *local_syms,
    asection **local_sections)
{
    struct elf_cris_link_hash_table *htab = elf_cris_hash_table(info);
    if (htab == NULL)
        return 0;

    bfd *dynobj = htab->root.dynobj;
    bfd_vma *local_got_offsets = elf_local_got_offsets(input_bfd);
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(input_bfd);
    Elf_Internal_Rela *rel, *relend = relocs + input_section->reloc_count;

    asection *sgot = NULL, *splt = NULL, *sreloc = NULL, *srelgot = NULL;

    if (dynobj != NULL) {
        splt = htab->root.splt;
        sgot = htab->root.sgot;
    }

    for (rel = relocs; rel < relend; rel++) {
        reloc_howto_type *howto;
        unsigned long r_symndx;
        Elf_Internal_Sym *sym = NULL;
        asection *sec = NULL;
        struct elf_link_hash_entry *h = NULL;
        bfd_vma relocation = 0;
        bfd_reloc_status_type r;
        const char *symname = NULL;
        enum elf_cris_reloc_type r_type;
        int resolved_to_zero = 0;

        r_type = ELF32_R_TYPE(rel->r_info);

        if (r_type == R_CRIS_GNU_VTINHERIT || r_type == R_CRIS_GNU_VTENTRY)
            continue;

        r_symndx = ELF32_R_SYM(rel->r_info);
        howto = cris_elf_howto_table + r_type;

        if (r_symndx < symtab_hdr->sh_info) {
            sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
            relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);

            symname = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link, sym->st_name);
            if (symname == NULL)
                symname = bfd_section_name(sec);
        } else {
            int warned = 0, ignored = 0, unresolved_reloc = 0;

            RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
                                   r_symndx, symtab_hdr, sym_hashes,
                                   h, sec, relocation,
                                   unresolved_reloc, warned, ignored);
            if (h)
                symname = h->root.root.string;

            if (unresolved_reloc && (sec && (sec->owner->flags & DYNAMIC) != 0)) {
                relocation = 0;
            } else if (h && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)) {
                if (bfd_link_pic(info)
                    && ((!SYMBOLIC_BIND(info, h) && h->dynindx != -1) || !h->def_regular)
                    && (input_section->flags & SEC_ALLOC) != 0
                    && (r_type == R_CRIS_8 || r_type == R_CRIS_16 || r_type == R_CRIS_32
                        || r_type == R_CRIS_8_PCREL || r_type == R_CRIS_16_PCREL
                        || r_type == R_CRIS_32_PCREL)) {
                    relocation = 0;
                } else if (!bfd_link_relocatable(info) && unresolved_reloc &&
                           (_bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset) != (bfd_vma)-1)) {
                    _bfd_error_handler(_("%pB, section %pA: unresolvable relocation %s against symbol `%s'"),
                        input_bfd, input_section, cris_elf_howto_table[r_type].name, symname);
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }
            }
        }

        if (sec && discarded_section(sec)) {
            RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
                                            rel, 1, relend, R_CRIS_NONE,
                                            howto, 0, contents);
        }

        if (bfd_link_relocatable(info))
            continue;

        resolved_to_zero = (h != NULL && UNDEFWEAK_NO_DYNAMIC_RELOC(info, h));

        switch (r_type) {
        case R_CRIS_16_GOTPLT:
        case R_CRIS_32_GOTPLT:
            if (h && ((struct elf_cris_link_hash_entry *)h)->gotplt_offset != 0) {
                asection *sgotplt = htab->root.sgotplt;
                bfd_vma got_offset;
                if (h->dynindx == (bfd_vma)-1 || sgotplt == NULL) {
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }
                got_offset = ((struct elf_cris_link_hash_entry *)h)->gotplt_offset;
                relocation = got_offset;
                break;
            }
            if (h && (h->got.offset == (bfd_vma)-1 ||
                      (!bfd_link_pic(info) &&
                       !(h->def_regular ||
                         (!h->def_dynamic && h->root.type == bfd_link_hash_undefweak))))) {
                _bfd_error_handler(
                    ((h->got.offset == (bfd_vma)-1) ?
                    _("%pB, section %pA: no PLT nor GOT for relocation %s against symbol `%s'") :
                    _("%pB, section %pA: no PLT for relocation %s against symbol `%s'")),
                    input_bfd, input_section,
                    cris_elf_howto_table[r_type].name,
                    (symname != NULL && symname[0] != '\0' ? symname : _("[whose name is lost]")));
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            /* fall through */
        case R_CRIS_16_GOT:
        case R_CRIS_32_GOT: {
            bfd_vma off = 0;
            if (h) {
                off = h->got.offset;
                if (off == (bfd_vma)-1) {
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }
                if (!elf_hash_table(info)->dynamic_sections_created
                    || (!bfd_link_pic(info) &&
                        (h->def_regular || h->type == STT_FUNC || h->needs_plt))
                    || (bfd_link_pic(info) &&
                        (SYMBOLIC_BIND(info, h) || h->dynindx == -1) && h->def_regular)) {
                    if ((off & 1) != 0)
                        off &= ~1;
                    else {
                        bfd_put_32(output_bfd, relocation, sgot->contents + off);
                        h->got.offset |= 1;
                    }
                }
            } else {
                if (!local_got_offsets || local_got_offsets[r_symndx] == (bfd_vma)-1) {
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }
                off = local_got_offsets[r_symndx];
                if ((off & 1) != 0)
                    off &= ~1;
                else {
                    bfd_put_32(output_bfd, relocation, sgot->contents + off);
                    if (bfd_link_pic(info)) {
                        Elf_Internal_Rela outrel;
                        bfd_byte *loc;
                        srelgot = htab->root.srelgot;
                        if (srelgot == NULL) {
                            bfd_set_error(bfd_error_bad_value);
                            return 0;
                        }
                        outrel.r_offset = (sgot->output_section->vma + sgot->output_offset + off);
                        outrel.r_info = ELF32_R_INFO(0, R_CRIS_RELATIVE);
                        outrel.r_addend = relocation;
                        loc = srelgot->contents + srelgot->reloc_count++ * sizeof(Elf32_External_Rela);
                        bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);
                    }
                    local_got_offsets[r_symndx] |= 1;
                }
            }
            relocation = sgot->output_offset + off;
            if (rel->r_addend != 0) {
                _bfd_error_handler(
                    h == NULL ?
                        _("%pB, section %pA: relocation %s with non-zero addend %" PRId64 " against local symbol") :
                        _("%pB, section %pA: relocation %s with non-zero addend %" PRId64 " against symbol `%s'"),
                    input_bfd, input_section, cris_elf_howto_table[r_type].name,
                    (int64_t)rel->r_addend,
                    (h && symname && symname[0] != '\0') ? symname : _("[whose name is lost]"));
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            break;
        }
        case R_CRIS_32_GOTREL:
            if (h && ELF_ST_VISIBILITY(h->other) == STV_DEFAULT &&
                !(!bfd_link_pic(info) &&
                  (h->def_regular || (!h->def_dynamic && h->root.type == bfd_link_hash_undefweak)))) {
                _bfd_error_handler(
                    _("%pB, section %pA: relocation %s is not allowed for global symbol: `%s'"),
                    input_bfd, input_section, cris_elf_howto_table[r_type].name, symname);
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            if (sgot == NULL) {
                _bfd_error_handler(
                    _("%pB, section %pA: relocation %s with no GOT created"),
                    input_bfd, input_section, cris_elf_howto_table[r_type].name);
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            relocation -= sgot->output_section->vma;
            break;
        case R_CRIS_32_PLT_PCREL:
            if (h == NULL || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT)
                break;
            if (h->plt.offset == (bfd_vma)-1 || splt == NULL)
                break;
            relocation = splt->output_section->vma + splt->output_offset + h->plt.offset;
            break;
        case R_CRIS_32_PLT_GOTREL:
            relocation -= sgot->output_section->vma;
            if (h == NULL || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT)
                break;
            if (h->plt.offset == (bfd_vma)-1 || splt == NULL)
                break;
            relocation = splt->output_section->vma + splt->output_offset + h->plt.offset - sgot->output_section->vma;
            break;
        case R_CRIS_8_PCREL:
        case R_CRIS_16_PCREL:
        case R_CRIS_32_PCREL:
            if (h == NULL || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT || h->dynindx == -1)
                break;
            /* fall through */
        case R_CRIS_8:
        case R_CRIS_16:
        case R_CRIS_32:
            if (bfd_link_pic(info) && !resolved_to_zero &&
                r_symndx != STN_UNDEF && (input_section->flags & SEC_ALLOC) != 0 &&
                ((r_type != R_CRIS_8_PCREL && r_type != R_CRIS_16_PCREL && r_type != R_CRIS_32_PCREL) ||
                 (!SYMBOLIC_BIND(info, h) || (h && !h->def_regular)))) {
                Elf_Internal_Rela outrel;
                bfd_byte *loc;
                int skip = 0, relocate = 0;
                if (sreloc == NULL) {
                    sreloc = _bfd_elf_get_dynamic_reloc_section(dynobj, input_section, 1);
                    if (sreloc == NULL) {
                        bfd_set_error(bfd_error_bad_value);
                        return 0;
                    }
                }
                outrel.r_offset = _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset);
                if (outrel.r_offset == (bfd_vma)-1) {
                    skip = 1;
                } else if (outrel.r_offset == (bfd_vma)-2 ||
                           (h != NULL && h->root.type == bfd_link_hash_undefweak && ELF_ST_VISIBILITY(h->other) != STV_DEFAULT)) {
                    skip = 1;
                    relocate = 1;
                }
                outrel.r_offset += input_section->output_section->vma + input_section->output_offset;
                if (skip)
                    memset(&outrel, 0, sizeof outrel);
                else if (h && ((!SYMBOLIC_BIND(info, h) && h->dynindx != -1) || !h->def_regular)) {
                    if (h->dynindx == -1) {
                        bfd_set_error(bfd_error_bad_value);
                        return 0;
                    }
                    outrel.r_info = ELF32_R_INFO(h->dynindx, r_type);
                    outrel.r_addend = relocation + rel->r_addend;
                } else {
                    outrel.r_addend = relocation + rel->r_addend;
                    if (r_type == R_CRIS_32) {
                        relocate = 1;
                        outrel.r_info = ELF32_R_INFO(0, R_CRIS_RELATIVE);
                    } else {
                        long indx;
                        if (bfd_is_abs_section(sec))
                            indx = 0;
                        else if (sec == NULL || sec->owner == NULL) {
                            bfd_set_error(bfd_error_bad_value);
                            return 0;
                        } else {
                            asection *osec = sec->output_section;
                            indx = elf_section_data(osec)->dynindx;
                            if (indx == 0) {
                                osec = htab->root.text_index_section;
                                indx = elf_section_data(osec)->dynindx;
                            }
                            if (indx == 0) {
                                bfd_set_error(bfd_error_bad_value);
                                return 0;
                            }
                        }
                        outrel.r_info = ELF32_R_INFO(indx, r_type);
                    }
                }
                loc = sreloc->contents + sreloc->reloc_count++ * sizeof(Elf32_External_Rela);
                bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);
                if (!relocate)
                    continue;
            }
            break;
        case R_CRIS_16_DTPREL:
        case R_CRIS_32_DTPREL:
            if (h && (input_section->flags & SEC_ALLOC) != 0 &&
                ELF_ST_VISIBILITY(h->other) == STV_DEFAULT &&
                (bfd_link_pic(info) || (!h->def_regular && h->root.type != bfd_link_hash_undefined))) {
                _bfd_error_handler(
                    (h->root.type == bfd_link_hash_undefined) ?
                        _("%pB, section %pA: relocation %s has an undefined reference to `%s', perhaps a declaration mixup?") :
                        _("%pB, section %pA: relocation %s is not allowed for `%s', a global symbol with default visibility, perhaps a declaration mixup?"),
                    input_bfd, input_section, cris_elf_howto_table[r_type].name,
                    (symname && symname[0] != '\0') ? symname : _("[whose name is lost]"));
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            if (((input_section->flags & SEC_ALLOC) != 0) && htab->dtpmod_refcount != 0) {
                asection *sgotplt = htab->root.sgotplt;
                if (sgotplt == NULL) {
                    bfd_set_error(bfd_error_bad_value);
                    return 0;
                }
                if (bfd_link_pic(info)) {
                    Elf_Internal_Rela outrel;
                    bfd_byte *loc;
                    srelgot = htab->root.srelgot;
                    if (srelgot == NULL) {
                        bfd_set_error(bfd_error_bad_value);
                        return 0;
                    }
                    loc = srelgot->contents + srelgot->reloc_count++ * sizeof(Elf32_External_Rela);

                    bfd_put_32(output_bfd, (bfd_vma)0, sgotplt->contents + 12);
                    bfd_put_32(output_bfd, (bfd_vma)0, sgotplt->contents + 16);
                    outrel.r_offset = sgotplt->output_section->vma + sgotplt->output_offset + 12;
                    outrel.r_info = ELF32_R_INFO(0, R_CRIS_DTPMOD);
                    outrel.r_addend = 0;
                    bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);
                } else {
                    bfd_put_32(output_bfd, (bfd_vma)1, sgotplt->contents + 12);
                    bfd_put_32(output_bfd, (bfd_vma)0, sgotplt->contents + 16);
                }
                htab->dtpmod_refcount = -htab->dtpmod_refcount;
            }
            if (elf_hash_table(info)->tls_sec != NULL)
                relocation -= elf_hash_table(info)->tls_sec->vma;
            break;
        case R_CRIS_32_GD:
            if (bfd_link_pic(info)) {
                bfd_set_error(bfd_error_invalid_operation);
                return 0;
            }
            /* fall through */
        case R_CRIS_16_GOT_GD:
        case R_CRIS_32_GOT_GD:
            if (rel->r_addend != 0) {
                _bfd_error_handler(
                    _("%pB, section %pA: relocation %s with non-zero addend %" PRId64 " against symbol `%s'"),
                    input_bfd, input_section, cris_elf_howto_table[r_type].name, (int64_t)rel->r_addend,
                    (symname && symname[0] != '\0') ? symname : _("[whose name is lost]"));
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            if (!bfd_link_pic(info) && (h == NULL || h->def_regular || ELF_COMMON_DEF_P(h))) {
                bfd_vma off;
                if (elf_hash_table(info)->tls_sec != NULL)
                    relocation -= elf_hash_table(info)->tls_sec->vma;
                if (h)
                    off = elf_cris_hash_entry(h)->tprel_refcount > 0 ? h->got.offset + 4 : h->got.offset;
                else {
                    off = local_got_offsets[r_symndx];
                    if (local_got_offsets[LGOT_TPREL_NDX(r_symndx)])
                        off += 4;
                }
                if ((off & 2) == 0) {
                    off &= ~3;
                    if (h)
                        h->got.offset |= 2;
                    else
                        local_got_offsets[r_symndx] |= 2;
                    bfd_put_32(output_bfd, 1, sgot->contents + off);
                    bfd_put_32(output_bfd, relocation, sgot->contents + off + 4);
                } else {
                    off &= ~3;
                }
                relocation = sgot->output_offset + off +
                             (r_type == R_CRIS_32_GD ? sgot->output_section->vma : 0);
            } else {
                bfd_vma off;
                if (h)
                    off = elf_cris_hash_entry(h)->tprel_refcount > 0 ? h->got.offset + 4 : h->got.offset;
                else {
                    off = local_got_offsets[r_symndx];
                    if (local_got_offsets[LGOT_TPREL_NDX(r_symndx)])
                        off += 4;
                }
                if ((off & 2) == 0) {
                    Elf_Internal_Rela outrel;
                    bfd_byte *loc;
                    off &= ~3;
                    if (h)
                        h->got.offset |= 2;
                    else
                        local_got_offsets[r_symndx] |= 2;
                    bfd_put_32(output_bfd, 0, sgot->contents + off);
                    bfd_put_32(output_bfd, 0, sgot->contents + off + 4);

                    srelgot = htab->root.srelgot;
                    if (srelgot == NULL) {
                        bfd_set_error(bfd_error_bad_value);
                        return 0;
                    }
                    if (h && h->dynindx != -1) {
                        outrel.r_info = ELF32_R_INFO(h->dynindx, R_CRIS_DTP);
                        relocation = 0;
                    } else {
                        outrel.r_info = ELF32_R_INFO(0, R_CRIS_DTP);
                        if (elf_hash_table(info)->tls_sec != NULL)
                            relocation -= elf_hash_table(info)->tls_sec->vma;
                    }
                    outrel.r_offset = sgot->output_section->vma + sgot->output_offset + off;
                    outrel.r_addend = relocation;
                    loc = srelgot->contents + srelgot->reloc_count++ * sizeof(Elf32_External_Rela);
                    if (srelgot->contents != NULL)
                        bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);
                } else {
                    off &= ~3;
                }
                relocation = sgot->output_offset + off +
                             (r_type == R_CRIS_32_GD ? sgot->output_section->vma : 0);
            }
            break;
        case R_CRIS_32_IE:
            if (bfd_link_pic(info)) {
                bfd_set_error(bfd_error_invalid_operation);
                return 0;
            }
            /* fall through */
        case R_CRIS_32_GOT_TPREL:
        case R_CRIS_16_GOT_TPREL:
            if (rel->r_addend != 0) {
                _bfd_error_handler(_("%pB, section %pA: relocation %s with non-zero addend %" PRId64 " against symbol `%s'"),
                        input_bfd, input_section, cris_elf_howto_table[r_type].name,
                        (int64_t)rel->r_addend, (symname && symname[0] != '\0') ? symname : _("[whose name is lost]"));
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            if (!bfd_link_pic(info) && (h == NULL || h->def_regular || ELF_COMMON_DEF_P(h))) {
                bfd_vma off;
                if (elf_hash_table(info)->tls_sec != NULL)
                    relocation -= elf_hash_table(info)->tls_sec->vma;
                relocation -= elf_hash_table(info)->tls_size;
                if (h)
                    off = h->got.offset;
                else
                    off = local_got_offsets[r_symndx];
                if ((off & 1) == 0) {
                    off &= ~3;
                    if (h)
                        h->got.offset |= 1;
                    else
                        local_got_offsets[r_symndx] |= 1;
                    bfd_put_32(output_bfd, relocation, sgot->contents + off);
                } else {
                    off &= ~3;
                }
                relocation = sgot->output_offset + off +
                             (r_type == R_CRIS_32_IE ? sgot->output_section->vma : 0);
            } else {
                bfd_vma off;
                if (h)
                    off = h->got.offset;
                else
                    off = local_got_offsets[r_symndx];
                if ((off & 1) == 0) {
                    Elf_Internal_Rela outrel;
                    bfd_byte *loc;
                    off &= ~3;
                    if (h)
                        h->got.offset |= 1;
                    else
                        local_got_offsets[r_symndx] |= 1;
                    srelgot = htab->root.srelgot;
                    if (srelgot == NULL) {
                        bfd_set_error(bfd_error_bad_value);
                        return 0;
                    }
                    if (h && h->dynindx != -1) {
                        outrel.r_info = ELF32_R_INFO(h->dynindx, R_CRIS_32_TPREL);
                        relocation = 0;
                    } else {
                        outrel.r_info = ELF32_R_INFO(0, R_CRIS_32_TPREL);
                        if (elf_hash_table(info)->tls_sec != NULL)
                            relocation -= elf_hash_table(info)->tls_sec->vma;
                    }
                    bfd_put_32(output_bfd, relocation, sgot->contents + off);
                    outrel.r_offset = sgot->output_section->vma + sgot->output_offset + off;
                    outrel.r_addend = relocation;
                    loc = srelgot->contents + srelgot->reloc_count++ * sizeof(Elf32_External_Rela);
                    if (srelgot->contents != NULL)
                        bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);
                } else {
                    off &= ~3;
                }
                relocation = sgot->output_offset + off +
                             (r_type == R_CRIS_32_IE ? sgot->output_section->vma : 0);
            }
            break;
        case R_CRIS_16_TPREL:
        case R_CRIS_32_TPREL:
            if (bfd_link_pic(info)) {
                bfd_set_error(bfd_error_invalid_operation);
                return 0;
            }
            if (h != NULL && ELF_ST_VISIBILITY(h->other) == STV_DEFAULT &&
                !(h->def_regular || ELF_COMMON_DEF_P(h)) &&
                h->root.type != bfd_link_hash_undefined) {
                _bfd_error_handler(
                    _("%pB, section %pA: relocation %s is not allowed for symbol: `%s' which is defined outside the program, perhaps a declaration mixup?"),
                    input_bfd, input_section, cris_elf_howto_table[r_type].name, symname);
                bfd_set_error(bfd_error_bad_value);
                return 0;
            }
            if (elf_hash_table(info)->tls_sec != NULL)
                relocation -= elf_hash_table(info)->tls_sec->vma + elf_hash_table(info)->tls_size;
            break;
        default:
            BFD_FAIL();
            return 0;
        }

        r = cris_final_link_relocate(howto, input_bfd, input_section, contents, rel, relocation);
        if (r != bfd_reloc_ok) {
            const char *msg = NULL;
            switch (r) {
            case bfd_reloc_overflow:
                (*info->callbacks->reloc_overflow)(info, (h ? &h->root : NULL),
                                                   symname, howto->name, (bfd_vma)0, input_bfd, input_section, rel->r_offset);
                if (additional_relocation_error_msg_count > 0) {
                    additional_relocation_error_msg_count--;
                    switch (r_type) {
                    case R_CRIS_16_GOTPLT:
                    case R_CRIS_16_GOT:
                    case R_CRIS_16_GOT_TPREL:
                    case R_CRIS_16_GOT_GD:
                        _bfd_error_handler(_("(too many global variables for -fpic: recompile with -fPIC)"));
                        break;
                    case R_CRIS_16_TPREL:
                    case R_CRIS_16_DTPREL:
                        _bfd_error_handler(_("(thread-local data too big for -fpic or -msmall-tls: recompile with -fPIC or -mno-small-tls)"));
                        break;
                    default:
                        break;
                    }
                }
                break;
            case bfd_reloc_undefined:
                (*info->callbacks->undefined_symbol)(info, symname, input_bfd, input_section, rel->r_offset, 1);
                break;
            case bfd_reloc_outofrange:
                msg = _("internal error: out of range error");
                break;
            case bfd_reloc_notsupported:
                msg = _("internal error: unsupported relocation error");
                break;
            case bfd_reloc_dangerous:
                msg = _("internal error: dangerous relocation");
                break;
            default:
                msg = _("internal error: unknown error");
                break;
            }
            if (msg)
                (*info->callbacks->warning)(info, msg, symname, input_bfd, input_section, rel->r_offset);
        }
    }
    return 1;
}


/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
elf_cris_finish_dynamic_symbol(bfd *output_bfd,
                              struct bfd_link_info *info,
                              struct elf_link_hash_entry *h,
                              Elf_Internal_Sym *sym)
{
    struct elf_cris_link_hash_table *htab = elf_cris_hash_table(info);

    int plt_off1 = 2, plt_off2 = 10, plt_off3 = 16;
    int plt_off3_value_bias = 4;
    int plt_stub_offset = 8;
    int plt_entry_size = PLT_ENTRY_SIZE;
    const bfd_byte *plt_entry = elf_cris_plt_entry;
    const bfd_byte *plt_pic_entry = elf_cris_pic_plt_entry;

    if (bfd_get_mach(output_bfd) == bfd_mach_cris_v32) {
        plt_off2 = 14;
        plt_off3 = 20;
        plt_off3_value_bias = -2;
        plt_stub_offset = 12;
        plt_entry_size = PLT_ENTRY_SIZE_V32;
        plt_entry = elf_cris_plt_entry_v32;
        plt_pic_entry = elf_cris_pic_plt_entry_v32;
    }

    if (h->plt.offset != (bfd_vma)-1) {
        asection *splt = htab->root.splt;
        asection *sgotplt = htab->root.sgotplt;
        asection *srela = htab->root.srelplt;
        bfd_vma gotplt_offset = elf_cris_hash_entry(h)->gotplt_offset;
        bool has_gotplt = (gotplt_offset != 0);
        bfd_vma rela_plt_index = (htab->dtpmod_refcount != 0)
            ? gotplt_offset/4 - 2 - 3
            : gotplt_offset/4 - 3;
        bfd_vma got_offset = has_gotplt
            ? gotplt_offset
            : h->got.offset + htab->next_gotplt_entry;
        bfd_vma got_base;
        Elf_Internal_Rela rela;
        bfd_byte *loc;

        if (!splt || !sgotplt || (has_gotplt && !srela))
            return false;

        got_base = sgotplt->output_section->vma + sgotplt->output_offset;

        if (!bfd_link_pic(info)) {
            memcpy(splt->contents + h->plt.offset, plt_entry, plt_entry_size);
            bfd_put_32(output_bfd, got_base + got_offset,
                       splt->contents + h->plt.offset + plt_off1);
        } else {
            memcpy(splt->contents + h->plt.offset, plt_pic_entry, plt_entry_size);
            bfd_put_32(output_bfd, got_offset,
                       splt->contents + h->plt.offset + plt_off1);
        }

        if (has_gotplt) {
            bfd_put_32(output_bfd,
                       rela_plt_index * sizeof(Elf32_External_Rela),
                       splt->contents + h->plt.offset + plt_off2);

            bfd_put_32(output_bfd,
                       -(h->plt.offset + plt_off3 + plt_off3_value_bias),
                       splt->contents + h->plt.offset + plt_off3);

            bfd_put_32(output_bfd,
                       (splt->output_section->vma
                        + splt->output_offset
                        + h->plt.offset
                        + plt_stub_offset),
                       sgotplt->contents + got_offset);

            rela.r_offset = (sgotplt->output_section->vma
                             + sgotplt->output_offset
                             + got_offset);
            rela.r_info = ELF32_R_INFO(h->dynindx, R_CRIS_JUMP_SLOT);
            rela.r_addend = 0;
            loc = srela->contents + rela_plt_index * sizeof(Elf32_External_Rela);
            bfd_elf32_swap_reloca_out(output_bfd, &rela, loc);
        }

        if (!h->def_regular) {
            sym->st_shndx = SHN_UNDEF;
            if (!h->ref_regular_nonweak)
                sym->st_value = 0;
        }
    }

    if (h->got.offset != (bfd_vma)-1 &&
        elf_cris_hash_entry(h)->reg_got_refcount > 0 &&
        (bfd_link_pic(info) ||
        (h->dynindx != -1 &&
         h->plt.offset == (bfd_vma)-1 &&
         !h->def_regular &&
         h->root.type != bfd_link_hash_undefweak))) {
        asection *sgot = htab->root.sgot;
        asection *srela = htab->root.srelgot;

        if (!sgot || !srela)
            return false;

        Elf_Internal_Rela rela;
        bfd_byte *loc;
        bfd_byte *where;
        bfd_vma offset = (h->got.offset & ~(bfd_vma)1);

        rela.r_offset = (sgot->output_section->vma
                         + sgot->output_offset
                         + offset);

        where = sgot->contents + offset;
        if (!elf_hash_table(info)->dynamic_sections_created ||
            (bfd_link_pic(info) &&
             (SYMBOLIC_BIND(info, h) || h->dynindx == -1) &&
             h->def_regular)) {
            rela.r_info = ELF32_R_INFO(0, R_CRIS_RELATIVE);
            rela.r_addend = bfd_get_signed_32(output_bfd, where);
        } else {
            bfd_put_32(output_bfd, (bfd_vma)0, where);
            rela.r_info = ELF32_R_INFO(h->dynindx, R_CRIS_GLOB_DAT);
            rela.r_addend = 0;
        }

        loc = srela->contents + srela->reloc_count * sizeof(Elf32_External_Rela);
        srela->reloc_count++;
        bfd_elf32_swap_reloca_out(output_bfd, &rela, loc);
    }

    if (h->needs_copy) {
        asection *s;
        if (h->dynindx == -1 ||
            (h->root.type != bfd_link_hash_defined &&
             h->root.type != bfd_link_hash_defweak))
            return false;
        if (h->root.u.def.section == htab->root.sdynrelro)
            s = htab->root.sreldynrelro;
        else
            s = htab->root.srelbss;

        Elf_Internal_Rela rela;
        bfd_byte *loc;
        rela.r_offset = (h->root.u.def.value
                         + h->root.u.def.section->output_section->vma
                         + h->root.u.def.section->output_offset);
        rela.r_info = ELF32_R_INFO(h->dynindx, R_CRIS_COPY);
        rela.r_addend = 0;
        loc = s->contents + s->reloc_count * sizeof(Elf32_External_Rela);
        s->reloc_count++;
        bfd_elf32_swap_reloca_out(output_bfd, &rela, loc);
    }

    if (h == elf_hash_table(info)->hdynamic ||
        h == elf_hash_table(info)->hgot)
        sym->st_shndx = SHN_ABS;

    return true;
}


/* Finish up the dynamic sections.  Do *not* emit relocs here, as their
   offsets were changed, as part of -z combreloc handling, from those we
   computed.  */

static bool elf_cris_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info) {
    bfd *dynobj = elf_hash_table(info)->dynobj;
    asection *sgot = elf_hash_table(info)->sgotplt;
    asection *sdyn = bfd_get_linker_section(dynobj, ".dynamic");

    if (!sgot) return false;

    if (elf_hash_table(info)->dynamic_sections_created) {
        asection *splt = elf_hash_table(info)->splt;
        if (!splt || !sdyn) return false;

        Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *)sdyn->contents;
        Elf32_External_Dyn *dynconend = (Elf32_External_Dyn *)(sdyn->contents + sdyn->size);

        for (; dyncon < dynconend; ++dyncon) {
            Elf_Internal_Dyn dyn;
            bfd_elf32_swap_dyn_in(dynobj, dyncon, &dyn);
            switch (dyn.d_tag) {
                case DT_PLTGOT:
                    dyn.d_un.d_ptr = sgot->output_section->vma + sgot->output_offset;
                    bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
                    break;
                case DT_JMPREL: {
                    asection *s = elf_hash_table(info)->srelplt;
                    dyn.d_un.d_ptr = s ? (s->output_section->vma + s->output_offset) : 0;
                    bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
                    break;
                }
                case DT_PLTRELSZ: {
                    asection *s = elf_hash_table(info)->srelplt;
                    dyn.d_un.d_val = s ? s->size : 0;
                    bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
                    break;
                }
                default:
                    break;
            }
        }

        if (splt->size > 0) {
            if (bfd_get_mach(output_bfd) == bfd_mach_cris_v32) {
                if (bfd_link_pic(info)) {
                    memcpy(splt->contents, elf_cris_pic_plt0_entry_v32, PLT_ENTRY_SIZE_V32);
                } else {
                    memcpy(splt->contents, elf_cris_plt0_entry_v32, PLT_ENTRY_SIZE_V32);
                    bfd_put_32(output_bfd, sgot->output_section->vma + sgot->output_offset + 4, splt->contents + 4);
                    elf_section_data(splt->output_section)->this_hdr.sh_entsize = PLT_ENTRY_SIZE_V32;
                }
            } else {
                if (bfd_link_pic(info)) {
                    memcpy(splt->contents, elf_cris_pic_plt0_entry, PLT_ENTRY_SIZE);
                } else {
                    memcpy(splt->contents, elf_cris_plt0_entry, PLT_ENTRY_SIZE);
                    bfd_put_32(output_bfd, sgot->output_section->vma + sgot->output_offset + 4, splt->contents + 6);
                    bfd_put_32(output_bfd, sgot->output_section->vma + sgot->output_offset + 8, splt->contents + 14);
                    elf_section_data(splt->output_section)->this_hdr.sh_entsize = PLT_ENTRY_SIZE;
                }
            }
        }
    }

    if (sgot->size > 0) {
        bfd_vma dyn_vma = sdyn ? sdyn->output_section->vma + sdyn->output_offset : 0;
        bfd_put_32(output_bfd, dyn_vma, sgot->contents);
        bfd_put_32(output_bfd, 0, sgot->contents + 4);
        bfd_put_32(output_bfd, 0, sgot->contents + 8);
    }

    elf_section_data(sgot->output_section)->this_hdr.sh_entsize = 4;
    return true;
}

/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *
cris_elf_gc_mark_hook(asection *sec,
                      struct bfd_link_info *info,
                      Elf_Internal_Rela *rel,
                      struct elf_link_hash_entry *h,
                      Elf_Internal_Sym *sym)
{
    enum elf_cris_reloc_type r_type;

    if (!rel)
        return NULL;

    r_type = ELF32_R_TYPE(rel->r_info);

    if (h) {
        if (r_type == R_CRIS_GNU_VTINHERIT || r_type == R_CRIS_GNU_VTENTRY)
            return NULL;
    }

    return _bfd_elf_gc_mark_hook(sec, info, rel, h, sym);
}

/* The elf_backend_plt_sym_val hook function.  */

static bfd_vma cris_elf_plt_sym_val(bfd_vma i ATTRIBUTE_UNUSED, const asection *plt, const arelent *rel) {
    bfd_size_type plt_entry_size;
    bfd_size_type pltoffs;
    bfd *abfd = plt->owner;
    bfd_size_type plt_entry_got_offset = 2;
    bfd_size_type plt_sec_size;
    bfd_size_type got_vma_for_dyn;
    asection *got;

    got = bfd_get_section_by_name(abfd, ".got");
    if (!got)
        return (bfd_vma)-1;

    plt_sec_size = bfd_section_size(plt);
    plt_entry_size = (bfd_get_mach(abfd) == bfd_mach_cris_v32)
                         ? PLT_ENTRY_SIZE_V32
                         : PLT_ENTRY_SIZE;
    got_vma_for_dyn = (abfd->flags & EXEC_P) ? 0 : got->vma;

    for (pltoffs = plt_entry_size; pltoffs < plt_sec_size; pltoffs += plt_entry_size) {
        bfd_size_type got_offset;
        bfd_byte gotoffs_raw[4];
        if (!bfd_get_section_contents(abfd, (asection *)plt, gotoffs_raw,
                                     pltoffs + plt_entry_got_offset,
                                     sizeof(gotoffs_raw))) {
            return (bfd_vma)-1;
        }
        got_offset = bfd_get_32(abfd, gotoffs_raw);
        if (got_offset + got_vma_for_dyn == rel->address)
            return plt->vma + pltoffs;
    }

    return (bfd_vma)-1;
}

/* Make sure we emit a GOT entry if the symbol was supposed to have a PLT
   entry but we found we will not create any.  Called when we find we will
   not have any PLT for this symbol, by for example
   elf_cris_adjust_dynamic_symbol when we're doing a proper dynamic link,
   or elf_cris_late_size_sections if no dynamic sections will be
   created (we're only linking static objects).  */

static bool
elf_cris_adjust_gotplt_to_got(struct elf_cris_link_hash_entry *h, void *p)
{
    struct bfd_link_info *info = (struct bfd_link_info *)p;
    asection *sgot;
    asection *srelgot;

    if (h == NULL || info == NULL)
        return false;

    if (h->gotplt_refcount <= 0)
        return true;

    if (h->gotplt_refcount != 0 &&
        h->root.plt.refcount != -1 &&
        h->gotplt_refcount > h->root.plt.refcount)
        return false;

    if (h->reg_got_refcount > 0) {
        h->root.got.refcount += h->gotplt_refcount;
        h->reg_got_refcount += h->gotplt_refcount;
        h->gotplt_refcount = 0;
        return true;
    }

    sgot = elf_hash_table(info)->sgot;
    srelgot = elf_hash_table(info)->srelgot;

    if (sgot == NULL || srelgot == NULL)
        return false;

    if (h->root.got.refcount < 0)
        return false;

    h->root.got.refcount += h->gotplt_refcount;
    h->reg_got_refcount = h->gotplt_refcount;
    h->gotplt_refcount = 0;

    sgot->size += 4;
    srelgot->size += sizeof(Elf32_External_Rela);

    return true;
}

/* Try to fold PLT entries with GOT entries.  There are two cases when we
   want to do this:

   - When all PLT references are GOTPLT references, and there are GOT
     references, and this is not the executable.  We don't have to
     generate a PLT at all.

   - When there are both (ordinary) PLT references and GOT references,
     and this isn't the executable.
     We want to make the PLT reference use the ordinary GOT entry rather
     than R_CRIS_JUMP_SLOT, a run-time dynamically resolved GOTPLT entry,
     since the GOT entry will have to be resolved at startup anyway.

   Though the latter case is handled when room for the PLT is allocated,
   not here.

   By folding into the GOT, we may need a round-trip to a PLT in the
   executable for calls, a loss in performance.  Still, losing a
   reloc is a win in size and at least in start-up time.

   Note that this function is called before symbols are forced local by
   version scripts.  The differing cases are handled by
   elf_cris_hide_symbol.  */

static bool elf_cris_try_fold_plt_to_got(struct elf_cris_link_hash_entry *h, void *p) {
    struct bfd_link_info *info = (struct bfd_link_info *)p;

    if (h->root.got.refcount <= 0 || h->root.plt.refcount <= 0) {
        return true;
    }

    if (h->gotplt_refcount > h->root.plt.refcount) {
        return false;
    }

    if (h->gotplt_refcount == h->root.plt.refcount) {
        if (!elf_cris_adjust_gotplt_to_got(h, info)) {
            return false;
        }
        h->root.plt.offset = (bfd_vma)-1;
    }

    return true;
}

/* Our own version of hide_symbol, so that we can adjust a GOTPLT reloc
   to use a GOT entry (and create one) rather than requiring a GOTPLT
   entry.  */

static void elf_cris_hide_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h, bool force_local) {
    if (!info || !h) {
        return;
    }

    elf_cris_adjust_gotplt_to_got((struct elf_cris_link_hash_entry *)h, info);
    _bfd_elf_link_hash_hide_symbol(info, h, force_local);
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool elf_cris_adjust_dynamic_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
    struct elf_cris_link_hash_table *htab = elf_cris_hash_table(info);
    if (htab == NULL)
        return false;

    bfd *dynobj = htab->root.dynobj;
    BFD_ASSERT(dynobj != NULL && (h->needs_plt || h->is_weakalias || (h->def_dynamic && h->ref_regular && !h->def_regular)));

    bfd_size_type plt_entry_size = (bfd_get_mach(dynobj) == bfd_mach_cris_v32) ? PLT_ENTRY_SIZE_V32 : PLT_ENTRY_SIZE;

    if (h->type == STT_FUNC || h->needs_plt) {
        if (!bfd_link_pic(info) && !h->def_dynamic) {
            BFD_ASSERT(h->needs_plt);
            h->needs_plt = 0;
            h->plt.offset = (bfd_vma)-1;
            return elf_cris_adjust_gotplt_to_got((struct elf_cris_link_hash_entry *)h, info);
        }

        if (bfd_link_pic(info) && !elf_cris_try_fold_plt_to_got((struct elf_cris_link_hash_entry *)h, info))
            return false;

        if (h->plt.refcount <= 0) {
            h->needs_plt = 0;
            h->plt.offset = (bfd_vma)-1;
            return true;
        }

        if (h->dynindx == -1) {
            if (!bfd_elf_link_record_dynamic_symbol(info, h))
                return false;
        }

        asection *s = htab->root.splt;
        BFD_ASSERT(s != NULL);

        if (s->size == 0)
            s->size += plt_entry_size;

        if (!bfd_link_pic(info) && !h->def_regular) {
            h->root.u.def.section = s;
            h->root.u.def.value = s->size;
        }

        if (bfd_link_pic(info) && h->got.refcount > 0) {
            h->got.refcount += h->plt.refcount;
            BFD_ASSERT((s->size % plt_entry_size) == 0);
            h->plt.offset = s->size;
            BFD_ASSERT(((struct elf_cris_link_hash_entry *)h)->gotplt_offset == 0);
            s->size += plt_entry_size;
            return true;
        }

        h->plt.offset = s->size;
        s->size += plt_entry_size;

        ((struct elf_cris_link_hash_entry *)h)->gotplt_offset = htab->next_gotplt_entry;
        htab->next_gotplt_entry += 4;

        s = htab->root.sgotplt;
        BFD_ASSERT(s != NULL);
        s->size += 4;

        s = htab->root.srelplt;
        BFD_ASSERT(s != NULL);
        s->size += sizeof(Elf32_External_Rela);

        return true;
    }

    h->plt.offset = (bfd_vma)-1;

    if (h->is_weakalias) {
        struct elf_link_hash_entry *def = weakdef(h);
        BFD_ASSERT(def->root.type == bfd_link_hash_defined);
        h->root.u.def.section = def->root.u.def.section;
        h->root.u.def.value = def->root.u.def.value;
        return true;
    }

    if (bfd_link_pic(info))
        return true;

    if (!h->non_got_ref)
        return true;

    asection *s = NULL, *srel = NULL;
    if ((h->root.u.def.section->flags & SEC_READONLY) != 0) {
        s = htab->root.sdynrelro;
        srel = htab->root.sreldynrelro;
    } else {
        s = htab->root.sdynbss;
        srel = htab->root.srelbss;
    }
    if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0) {
        BFD_ASSERT(srel != NULL);
        srel->size += sizeof(Elf32_External_Rela);
        h->needs_copy = 1;
    }
    BFD_ASSERT(s != NULL);

    return _bfd_elf_adjust_dynamic_copy(info, h, s);
}

/* Adjust our "subclass" elements for an indirect symbol.  */

static void elf_cris_copy_indirect_symbol(struct bfd_link_info *info,
                                          struct elf_link_hash_entry *dir,
                                          struct elf_link_hash_entry *ind)
{
    struct elf_cris_link_hash_entry *edir = (struct elf_cris_link_hash_entry *)dir;
    struct elf_cris_link_hash_entry *eind = (struct elf_cris_link_hash_entry *)ind;

    if (eind->root.root.type != bfd_link_hash_indirect) {
        _bfd_elf_link_hash_copy_indirect(info, dir, ind);
        return;
    }

    if (edir->gotplt_offset != 0 && eind->gotplt_offset != 0) {
        return;
    }

    if (eind->pcrel_relocs_copied != NULL) {
        if (edir->pcrel_relocs_copied != NULL) {
            struct elf_cris_pcrel_relocs_copied **pp = &eind->pcrel_relocs_copied;
            while (*pp != NULL) {
                struct elf_cris_pcrel_relocs_copied *p = *pp;
                struct elf_cris_pcrel_relocs_copied *q = edir->pcrel_relocs_copied;
                while (q != NULL) {
                    if (q->section == p->section) {
                        q->count += p->count;
                        *pp = p->next;
                        p = NULL;
                        break;
                    }
                    q = q->next;
                }
                if (p != NULL)
                    pp = &p->next;
            }
            *pp = edir->pcrel_relocs_copied;
        }
        edir->pcrel_relocs_copied = eind->pcrel_relocs_copied;
        eind->pcrel_relocs_copied = NULL;
    }

    edir->gotplt_refcount   += eind->gotplt_refcount;
    eind->gotplt_refcount    = 0;
    edir->gotplt_offset     += eind->gotplt_offset;
    eind->gotplt_offset      = 0;
    edir->reg_got_refcount  += eind->reg_got_refcount;
    eind->reg_got_refcount   = 0;
    edir->tprel_refcount    += eind->tprel_refcount;
    eind->tprel_refcount     = 0;
    edir->dtp_refcount      += eind->dtp_refcount;
    eind->dtp_refcount       = 0;

    _bfd_elf_link_hash_copy_indirect(info, dir, ind);
}

/* Look through the relocs for a section during the first phase.  */

static bool cris_elf_check_relocs(bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela *relocs)
{
    struct elf_cris_link_hash_table *htab;
    bfd *dynobj;
    Elf_Internal_Shdr *symtab_hdr;
    struct elf_link_hash_entry **sym_hashes;
    bfd_signed_vma *local_got_refcounts;
    const Elf_Internal_Rela *rel, *rel_end;
    asection *sgot = NULL;
    asection *srelgot = NULL;
    asection *sreloc = NULL;

    if (bfd_link_relocatable(info))
        return true;

    htab = elf_cris_hash_table(info);
    if (!htab)
        return false;

    dynobj = elf_hash_table(info)->dynobj;
    symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
    sym_hashes = elf_sym_hashes(abfd);
    local_got_refcounts = elf_local_got_refcounts(abfd);

    rel_end = relocs + sec->reloc_count;
    for (rel = relocs; rel < rel_end; rel++) {
        struct elf_link_hash_entry *h = NULL;
        unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
        enum elf_cris_reloc_type r_type = ELF32_R_TYPE(rel->r_info);
        bfd_signed_vma got_element_size = 4;
        unsigned long r_symndx_lgot = INT_MAX;

        if (r_symndx < symtab_hdr->sh_info) {
            r_symndx_lgot = LGOT_REG_NDX(r_symndx);
        } else {
            h = sym_hashes[r_symndx - symtab_hdr->sh_info];
            while (h && (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning))
                h = (struct elf_link_hash_entry *)h->root.u.i.link;
        }

        switch (r_type) {
            case R_CRIS_32_DTPREL:
                if ((sec->flags & SEC_ALLOC) == 0)
                    continue;
            case R_CRIS_16_DTPREL:
                if (htab->dtpmod_refcount == 0)
                    htab->next_gotplt_entry += 8;
                htab->dtpmod_refcount++;
            case R_CRIS_32_IE:
            case R_CRIS_32_GD:
            case R_CRIS_16_GOT_GD:
            case R_CRIS_32_GOT_GD:
            case R_CRIS_32_GOT_TPREL:
            case R_CRIS_16_GOT_TPREL:
            case R_CRIS_16_GOT:
            case R_CRIS_32_GOT:
            case R_CRIS_32_GOTREL:
            case R_CRIS_32_PLT_GOTREL:
            case R_CRIS_32_PLT_PCREL:
            case R_CRIS_16_GOTPLT:
            case R_CRIS_32_GOTPLT:
                if (!dynobj) {
                    elf_hash_table(info)->dynobj = dynobj = abfd;
                    if (bfd_get_mach(dynobj) == bfd_mach_cris_v10_v32) {
                        _bfd_error_handler(
                            _("%pB, section %pA: v10/v32 compatible object must not contain a PIC relocation"),
                            abfd, sec);
                        return false;
                    }
                }
                if (!sgot) {
                    if (!_bfd_elf_create_got_section(dynobj, info))
                        return false;
                    sgot = elf_hash_table(info)->sgot;
                    srelgot = elf_hash_table(info)->srelgot;
                }
                if (!local_got_refcounts) {
                    bfd_size_type amt;
                    amt = LGOT_ALLOC_NELTS_FOR(symtab_hdr->sh_info) + 1;
                    amt *= sizeof(bfd_signed_vma);
                    local_got_refcounts = (bfd_signed_vma *)bfd_zalloc(abfd, amt);
                    if (!local_got_refcounts)
                        return false;
                    local_got_refcounts++;
                    elf_local_got_refcounts(abfd) = local_got_refcounts;
                }
                break;
            default:
                break;
        }

        switch (r_type) {
            case R_CRIS_32_IE:
            case R_CRIS_32_TPREL:
            case R_CRIS_16_TPREL:
            case R_CRIS_32_GD:
                if (bfd_link_pic(info)) {
                    _bfd_error_handler(
                        _("%pB, section %pA:\n  relocation %s not valid in a shared object; typically an option mixup, recompile with -fPIC"),
                        abfd, sec, cris_elf_howto_table[r_type].name);
                }
            default:
                break;
        }

        switch (r_type) {
            case R_CRIS_32_GD:
            case R_CRIS_16_GOT_GD:
            case R_CRIS_32_GOT_GD:
                got_element_size = 8;
                r_symndx_lgot = LGOT_DTP_NDX(r_symndx);
                break;
            case R_CRIS_16_DTPREL:
            case R_CRIS_32_DTPREL:
                break;
            case R_CRIS_32_IE:
            case R_CRIS_32_GOT_TPREL:
            case R_CRIS_16_GOT_TPREL:
                r_symndx_lgot = LGOT_TPREL_NDX(r_symndx);
                if (bfd_link_pic(info))
                    info->flags |= DF_STATIC_TLS;
                break;
            case R_CRIS_16_TPREL:
            case R_CRIS_32_TPREL:
            default:
                break;
        }

        switch (r_type) {
            case R_CRIS_16_GOTPLT:
            case R_CRIS_32_GOTPLT:
                if (h) {
                    elf_cris_hash_entry(h)->gotplt_refcount++;
                    goto handle_gotplt_reloc_label;
                }
            case R_CRIS_32_IE:
            case R_CRIS_32_GD:
            case R_CRIS_16_GOT_GD:
            case R_CRIS_32_GOT_GD:
            case R_CRIS_32_GOT_TPREL:
            case R_CRIS_16_GOT_TPREL:
            case R_CRIS_16_GOT:
            case R_CRIS_32_GOT:
                if (h) {
                    if (!h->got.refcount) {
                        if (h->dynindx == -1) {
                            if (!bfd_elf_link_record_dynamic_symbol(info, h))
                                return false;
                        }
                    }
                    h->got.refcount++;
                    switch (r_type) {
                        case R_CRIS_16_GOT:
                        case R_CRIS_32_GOT:
                            if (!elf_cris_hash_entry(h)->reg_got_refcount) {
                                if (sgot) sgot->size += got_element_size;
                                if (srelgot) srelgot->size += sizeof(Elf32_External_Rela);
                            }
                            elf_cris_hash_entry(h)->reg_got_refcount++;
                            break;
                        case R_CRIS_32_GD:
                        case R_CRIS_16_GOT_GD:
                        case R_CRIS_32_GOT_GD:
                            if (!elf_cris_hash_entry(h)->dtp_refcount) {
                                if (sgot) sgot->size += got_element_size;
                                if (srelgot) srelgot->size += sizeof(Elf32_External_Rela);
                            }
                            elf_cris_hash_entry(h)->dtp_refcount++;
                            break;
                        case R_CRIS_32_IE:
                        case R_CRIS_32_GOT_TPREL:
                        case R_CRIS_16_GOT_TPREL:
                            if (!elf_cris_hash_entry(h)->tprel_refcount) {
                                if (sgot) sgot->size += got_element_size;
                                if (srelgot) srelgot->size += sizeof(Elf32_External_Rela);
                            }
                            elf_cris_hash_entry(h)->tprel_refcount++;
                            break;
                        default:
                            BFD_FAIL();
                            break;
                    }
                } else if (local_got_refcounts) {
                    if (!local_got_refcounts[r_symndx_lgot]) {
                        if (sgot) sgot->size += got_element_size;
                        if (bfd_link_pic(info) && srelgot)
                            srelgot->size += sizeof(Elf32_External_Rela);
                    }
                    local_got_refcounts[r_symndx_lgot]++;
                    local_got_refcounts[r_symndx]++;
                }
                break;
            case R_CRIS_16_DTPREL:
            case R_CRIS_32_DTPREL:
            case R_CRIS_32_GOTREL:
                if (local_got_refcounts)
                    local_got_refcounts[-1]++;
                break;
handle_gotplt_reloc_label:
            case R_CRIS_32_PLT_GOTREL:
                if (local_got_refcounts)
                    local_got_refcounts[-1]++;
            case R_CRIS_32_PLT_PCREL:
                if (!h)
                    continue;
                h->needs_plt = 1;
                if (h->plt.refcount != -1)
                    h->plt.refcount++;
                break;
            case R_CRIS_8:
            case R_CRIS_16:
            case R_CRIS_32:
                if (bfd_link_pic(info) && (sec->flags & SEC_ALLOC) && (sec->flags & SEC_READONLY)) {
                    _bfd_error_handler(
                        _("%pB, section %pA: relocation %s should not be used in a shared object; recompile with -fPIC"),
                        abfd, sec, cris_elf_howto_table[r_type].name);
                }
                if ((sec->flags & SEC_ALLOC) == 0)
                    break;
                if (h) {
                    h->non_got_ref = 1;
                    if (ELF_ST_VISIBILITY(h->other) == STV_DEFAULT)
                        h->plt.refcount++;
                }
                if (!bfd_link_pic(info) ||
                    (h && UNDEFWEAK_NO_DYNAMIC_RELOC(info, h)))
                    break;
                if (!sreloc) {
                    sreloc = _bfd_elf_make_dynamic_reloc_section(sec, dynobj, 2, abfd, 1);
                    if (!sreloc)
                        return false;
                }
                if (sec->flags & SEC_READONLY)
                    info->flags |= DF_TEXTREL;
                sreloc->size += sizeof(Elf32_External_Rela);
                break;
            case R_CRIS_8_PCREL:
            case R_CRIS_16_PCREL:
            case R_CRIS_32_PCREL:
                if (h) {
                    h->non_got_ref = 1;
                    if (ELF_ST_VISIBILITY(h->other) == STV_DEFAULT)
                        h->plt.refcount++;
                }
                if (!bfd_link_pic(info) || (sec->flags & SEC_ALLOC) == 0)
                    break;
                if (!h || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT)
                    break;
                if (SYMBOLIC_BIND(info, h) &&
                    h->root.type != bfd_link_hash_defweak &&
                    h->def_regular)
                    break;
                if (!sreloc) {
                    sreloc = _bfd_elf_make_dynamic_reloc_section(sec, dynobj, 2, abfd, 1);
                    if (!sreloc)
                        return false;
                }
                sreloc->size += sizeof(Elf32_External_Rela);
                {
                    struct elf_cris_link_hash_entry *eh = elf_cris_hash_entry(h);
                    struct elf_cris_pcrel_relocs_copied *p;
                    for (p = eh->pcrel_relocs_copied; p; p = p->next) {
                        if (p->section == sec)
                            break;
                    }
                    if (!p) {
                        p = (struct elf_cris_pcrel_relocs_copied *)bfd_alloc(dynobj, (bfd_size_type)sizeof(*p));
                        if (!p)
                            return false;
                        p->next = eh->pcrel_relocs_copied;
                        eh->pcrel_relocs_copied = p;
                        p->section = sec;
                        p->count = 0;
                        p->r_type = r_type;
                    }
                    ++p->count;
                }
                break;
            case R_CRIS_GNU_VTINHERIT:
                if (!bfd_elf_gc_record_vtinherit(abfd, sec, h, rel->r_offset))
                    return false;
                break;
            case R_CRIS_GNU_VTENTRY:
                if (!bfd_elf_gc_record_vtentry(abfd, sec, h, rel->r_addend))
                    return false;
                break;
            case R_CRIS_16_TPREL:
            case R_CRIS_32_TPREL:
                break;
            default:
                bfd_set_error(bfd_error_bad_value);
                return false;
        }
    }
    return true;
}


/* Set the sizes of the dynamic sections.  */

static bool
elf_cris_late_size_sections(bfd *output_bfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  struct elf_cris_link_hash_table *htab = elf_cris_hash_table(info);
  if (htab == NULL)
    return false;

  bfd *dynobj = htab->root.dynobj;
  if (dynobj == NULL)
    return true;

  if (htab->root.dynamic_sections_created) {
    if (bfd_link_executable(info) && !info->nointerp) {
      asection *s = bfd_get_linker_section(dynobj, ".interp");
      if (s == NULL)
        return false;
      s->size = sizeof ELF_DYNAMIC_INTERPRETER;
      s->contents = (unsigned char *)ELF_DYNAMIC_INTERPRETER;
      s->alloced = 1;
    }
  } else {
    elf_cris_link_hash_traverse(htab, elf_cris_adjust_gotplt_to_got, info);
    if (htab->root.srelgot)
      htab->root.srelgot->size = 0;
  }

  if (bfd_link_pic(info))
    elf_cris_link_hash_traverse(htab, elf_cris_discard_excess_dso_dynamics, info);
  else
    elf_cris_link_hash_traverse(htab, elf_cris_discard_excess_program_dynamics, info);

  bool relocs = false;
  for (asection *s = dynobj->sections; s != NULL; s = s->next) {
    if ((s->flags & SEC_LINKER_CREATED) == 0)
      continue;

    const char *name = bfd_section_name(s);
    if (name == NULL)
      continue;

    if (!strcmp(name, ".plt")) {
      // Nothing to do
    } else if (!strcmp(name, ".got.plt")) {
      if (htab->dtpmod_refcount != 0)
        s->size += 8;
    } else if (startswith(name, ".rela")) {
      if (!strcmp(name, ".rela.got") && htab->dtpmod_refcount != 0 && bfd_link_pic(info))
        s->size += sizeof(Elf32_External_Rela);

      if (s->size != 0) {
        if (strcmp(name, ".rela.plt"))
          relocs = true;
        s->reloc_count = 0;
      }
    } else if (!startswith(name, ".got") &&
               strcmp(name, ".dynbss") != 0 &&
               s != htab->root.sdynrelro) {
      continue;
    }

    if (s->size == 0) {
      s->flags |= SEC_EXCLUDE;
      continue;
    }

    if ((s->flags & SEC_HAS_CONTENTS) == 0)
      continue;

    s->contents = (bfd_byte *)bfd_zalloc(dynobj, s->size);
    if (s->contents == NULL)
      return false;
    s->alloced = 1;
  }

  return _bfd_elf_add_dynamic_tags(output_bfd, info, relocs);
}

/* This function is called via elf_cris_link_hash_traverse if we are
   creating a shared object.  In the -Bsymbolic case, it discards the
   space allocated to copy PC relative relocs against symbols which
   are defined in regular objects.  For the normal non-symbolic case,
   we also discard space for relocs that have become local due to
   symbol visibility changes.  We allocated space for them in the
   check_relocs routine, but we won't fill them in in the
   relocate_section routine.  */

static bool elf_cris_discard_excess_dso_dynamics(struct elf_cris_link_hash_entry *h, void *inf) {
    struct elf_cris_pcrel_relocs_copied *s = h->pcrel_relocs_copied;
    struct bfd_link_info *info = (struct bfd_link_info *)inf;

    if (h->root.def_regular && (h->root.forced_local || SYMBOLIC_BIND(info, &h->root))) {
        for (; s != NULL; s = s->next) {
            asection *sreloc = _bfd_elf_get_dynamic_reloc_section(
                elf_hash_table(info)->dynobj,
                s->section,
                true
            );
            if (sreloc && sreloc->size >= s->count * sizeof(Elf32_External_Rela)) {
                sreloc->size -= s->count * sizeof(Elf32_External_Rela);
            }
        }
        return true;
    }

    for (s = h->pcrel_relocs_copied; s != NULL; s = s->next) {
        if ((s->section->flags & SEC_READONLY) != 0) {
            _bfd_error_handler(
                _("%pB, section `%pA', to symbol `%s': relocation %s should not be used in a shared object; recompile with -fPIC"),
                s->section->owner,
                s->section,
                h->root.root.root.string,
                cris_elf_howto_table[s->r_type].name
            );
            info->flags |= DF_TEXTREL;
        }
    }

    return true;
}

/* This function is called via elf_cris_link_hash_traverse if we are *not*
   creating a shared object.  We discard space for relocs for symbols put
   in the .got, but which we found we do not have to resolve at run-time.  */

static bool elf_cris_discard_excess_program_dynamics(struct elf_cris_link_hash_entry *h, void *inf)
{
    struct bfd_link_info *info = (struct bfd_link_info *)inf;
    struct elf_link_hash_entry *root = &h->root;
    struct elf_link_hash_table *hash_table = elf_hash_table(info);

    if (!root->def_dynamic || root->plt.refcount > 0) {
        if (h->reg_got_refcount > 0 && hash_table->dynamic_sections_created) {
            bfd *dynobj = hash_table->dynobj;
            asection *srelgot = hash_table->srelgot;

            if (dynobj == NULL || srelgot == NULL) {
                return false;
            }

            if (srelgot->size >= sizeof(Elf32_External_Rela)) {
                srelgot->size -= sizeof(Elf32_External_Rela);
            } else {
                srelgot->size = 0;
            }
        }

        if (!(info->export_dynamic ||
              (root->type != STT_FUNC && info->dynamic_data)) &&
              root->dynindx != -1 &&
              !root->dynamic &&
              !root->def_dynamic &&
              !root->ref_dynamic)
        {
            root->dynindx = -1;
            _bfd_elf_strtab_delref(hash_table->dynstr, root->dynstr_index);
        }
    }
    return true;
}

/* Reject a file depending on presence and expectation of prefixed
   underscores on symbols.  */

static bool cris_elf_object_p(bfd *abfd)
{
    int leading_char;

    if (!cris_elf_set_mach_from_flags(abfd, elf_elfheader(abfd)->e_flags))
        return false;

    leading_char = bfd_get_symbol_leading_char(abfd);

    if (elf_elfheader(abfd)->e_flags & EF_CRIS_UNDERSCORE)
        return leading_char == '_';

    return leading_char == 0;
}

/* Mark presence or absence of leading underscore.  Set machine type
   flags from mach type.  */

static bool cris_elf_final_write_processing(bfd *abfd)
{
    unsigned long e_flags;
    int leading_char;
    int mach;

    if (!abfd)
        return false;

    e_flags = elf_elfheader(abfd)->e_flags;

    e_flags &= ~EF_CRIS_UNDERSCORE;

    leading_char = bfd_get_symbol_leading_char(abfd);
    if (leading_char == '_')
        e_flags |= EF_CRIS_UNDERSCORE;

    mach = bfd_get_mach(abfd);
    if (mach == bfd_mach_cris_v0_v10) {
        e_flags |= EF_CRIS_VARIANT_ANY_V0_V10;
    } else if (mach == bfd_mach_cris_v10_v32) {
        e_flags |= EF_CRIS_VARIANT_COMMON_V10_V32;
    } else if (mach == bfd_mach_cris_v32) {
        e_flags |= EF_CRIS_VARIANT_V32;
    } else {
        _bfd_abort(__FILE__, __LINE__, _("unexpected machine number"));
        return false;
    }

    elf_elfheader(abfd)->e_flags = e_flags;

    return _bfd_elf_final_write_processing(abfd);
}

/* Set the mach type from e_flags value.  */

static bool cris_elf_set_mach_from_flags(bfd *abfd, unsigned long flags) {
    int variant = flags & EF_CRIS_VARIANT_MASK;
    bool result = true;

    if (abfd == NULL) {
        bfd_set_error(bfd_error_invalid_operation);
        return false;
    }

    switch (variant) {
        case EF_CRIS_VARIANT_ANY_V0_V10:
            result = bfd_default_set_arch_mach(abfd, bfd_arch_cris, bfd_mach_cris_v0_v10);
            break;
        case EF_CRIS_VARIANT_V32:
            result = bfd_default_set_arch_mach(abfd, bfd_arch_cris, bfd_mach_cris_v32);
            break;
        case EF_CRIS_VARIANT_COMMON_V10_V32:
            result = bfd_default_set_arch_mach(abfd, bfd_arch_cris, bfd_mach_cris_v10_v32);
            break;
        default:
            bfd_set_error(bfd_error_wrong_format);
            return false;
    }

    if (!result) {
        bfd_set_error(bfd_error_invalid_operation);
        return false;
    }
    return true;
}

/* Display the flags field.  */

static bool cris_elf_print_private_bfd_data(bfd *abfd, void *ptr)
{
    if (abfd == NULL || ptr == NULL)
        return false;

    FILE *file = (FILE *)ptr;

    if (!_bfd_elf_print_private_bfd_data(abfd, ptr))
        return false;

    unsigned long flags = elf_elfheader(abfd)->e_flags;
    if (fprintf(file, _("private flags = %lx:"), flags) < 0)
        return false;

    if (flags & EF_CRIS_UNDERSCORE)
        if (fprintf(file, _(" [symbols have a _ prefix]")) < 0)
            return false;

    if ((flags & EF_CRIS_VARIANT_MASK) == EF_CRIS_VARIANT_COMMON_V10_V32)
        if (fprintf(file, _(" [v10 and v32]")) < 0)
            return false;

    if ((flags & EF_CRIS_VARIANT_MASK) == EF_CRIS_VARIANT_V32)
        if (fprintf(file, _(" [v32]")) < 0)
            return false;

    if (fputc('\n', file) == EOF)
        return false;

    return true;
}

/* Don't mix files with and without a leading underscore.  */

static bool cris_elf_merge_private_bfd_data(bfd *ibfd, struct bfd_link_info *info)
{
    bfd *obfd = info->output_bfd;
    int imach, omach;

    if (!_bfd_generic_verify_endian_match(ibfd, info))
        return false;

    if (bfd_get_flavour(ibfd) != bfd_target_elf_flavour ||
        bfd_get_flavour(obfd) != bfd_target_elf_flavour)
        return true;

    imach = bfd_get_mach(ibfd);

    if (!elf_flags_init(obfd))
    {
        elf_flags_init(obfd) = true;
        if (!bfd_set_arch_mach(obfd, bfd_arch_cris, imach))
            return false;
    }

    if (bfd_get_symbol_leading_char(ibfd) != bfd_get_symbol_leading_char(obfd))
    {
        const char *msg;
        if (bfd_get_symbol_leading_char(ibfd) == '_')
            msg = _("%pB: uses _-prefixed symbols, but writing file with non-prefixed symbols");
        else
            msg = _("%pB: uses non-prefixed symbols, but writing file with _-prefixed symbols");
        _bfd_error_handler(msg, ibfd);
        bfd_set_error(bfd_error_bad_value);
        return false;
    }

    omach = bfd_get_mach(obfd);

    if (imach != omach)
    {
        bool imach_v32 = (imach == bfd_mach_cris_v32);
        bool omach_v32 = (omach == bfd_mach_cris_v32);
        bool omach_v10_v32 = (omach == bfd_mach_cris_v10_v32);
        bool imach_v10_v32 = (imach == bfd_mach_cris_v10_v32);

        if ((imach_v32 && !omach_v10_v32) || (omach_v32 && !imach_v10_v32))
        {
            const char *msg = imach_v32
                ? _("%pB contains CRIS v32 code, incompatible with previous objects")
                : _("%pB contains non-CRIS-v32 code, incompatible with previous objects");
            _bfd_error_handler(msg, ibfd);
            bfd_set_error(bfd_error_bad_value);
            return false;
        }

        if (omach_v10_v32 && !bfd_set_arch_mach(obfd, bfd_arch_cris, imach))
            return false;
    }

    return true;
}

/* Do side-effects of e_flags copying to obfd.  */

static bool cris_elf_copy_private_bfd_data(bfd *ibfd, bfd *obfd)
{
    if (!ibfd || !obfd)
        return false;

    if (bfd_get_flavour(ibfd) != bfd_target_elf_flavour ||
        bfd_get_flavour(obfd) != bfd_target_elf_flavour)
        return true;

    if (!_bfd_elf_copy_private_bfd_data(ibfd, obfd))
        return false;

    return bfd_set_arch_mach(obfd, bfd_arch_cris, bfd_get_mach(ibfd)) ? true : false;
}

static enum elf_reloc_type_class
elf_cris_reloc_type_class(const struct bfd_link_info *info, const asection *rel_sec, const Elf_Internal_Rela *rela)
{
    switch (ELF32_R_TYPE(rela->r_info)) {
        case R_CRIS_RELATIVE:
            return reloc_class_relative;
        case R_CRIS_JUMP_SLOT:
            return reloc_class_plt;
        case R_CRIS_COPY:
            return reloc_class_copy;
        default:
            return reloc_class_normal;
    }
}

/* The elf_backend_got_elt_size worker.  For one symbol, we can have up to
   two GOT entries from three types with two different sizes.  We handle
   it as a single entry, so we can use the regular offset-calculation
   machinery.  */

static bfd_vma elf_cris_got_elt_size(bfd *abfd ATTRIBUTE_UNUSED,
                                     struct bfd_link_info *info ATTRIBUTE_UNUSED,
                                     struct elf_link_hash_entry *hr,
                                     bfd *ibfd,
                                     unsigned long symndx)
{
    bfd_vma eltsiz = 0;

    if (hr == NULL) {
        bfd_signed_vma *local_got_refcounts = elf_local_got_refcounts(ibfd);
        if (local_got_refcounts == NULL) {
            return 0;
        }

        if (local_got_refcounts[LGOT_REG_NDX(symndx)] > 0) {
            if (local_got_refcounts[LGOT_DTP_NDX(symndx)] != 0 ||
                local_got_refcounts[LGOT_TPREL_NDX(symndx)] != 0) {
                return 0;
            }
            return 4;
        }

        if (local_got_refcounts[LGOT_DTP_NDX(symndx)] > 0) {
            eltsiz += 8;
        }
        if (local_got_refcounts[LGOT_TPREL_NDX(symndx)] > 0) {
            eltsiz += 4;
        }
    } else {
        struct elf_cris_link_hash_entry *hh = elf_cris_hash_entry(hr);

        if (hh->reg_got_refcount > 0) {
            if (hh->dtp_refcount != 0 || hh->tprel_refcount != 0) {
                return 0;
            }
            return 4;
        }

        if (hh->dtp_refcount > 0) {
            eltsiz += 8;
        }
        if (hh->tprel_refcount > 0) {
            eltsiz += 4;
        }
    }

    if (eltsiz == 0) {
        return 0;
    }
    return eltsiz;
}

#define ELF_ARCH		bfd_arch_cris
#define ELF_TARGET_ID		CRIS_ELF_DATA
#define ELF_MACHINE_CODE	EM_CRIS
#define ELF_MAXPAGESIZE		0x2000

#define TARGET_LITTLE_SYM	cris_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-cris"
#define elf_symbol_leading_char 0

#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			cris_info_to_howto_rela
#define elf_backend_relocate_section		cris_elf_relocate_section
#define elf_backend_gc_mark_hook		cris_elf_gc_mark_hook
#define elf_backend_plt_sym_val			cris_elf_plt_sym_val
#define elf_backend_check_relocs		cris_elf_check_relocs
#define elf_backend_grok_prstatus		cris_elf_grok_prstatus
#define elf_backend_grok_psinfo			cris_elf_grok_psinfo

#define elf_backend_can_gc_sections		1
#define elf_backend_can_refcount		1

#define elf_backend_object_p			cris_elf_object_p
#define elf_backend_final_write_processing \
	cris_elf_final_write_processing
#define bfd_elf32_bfd_print_private_bfd_data \
	cris_elf_print_private_bfd_data
#define bfd_elf32_bfd_merge_private_bfd_data \
	cris_elf_merge_private_bfd_data
#define bfd_elf32_bfd_copy_private_bfd_data \
	cris_elf_copy_private_bfd_data

#define bfd_elf32_bfd_reloc_type_lookup		cris_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup	cris_reloc_name_lookup

#define bfd_elf32_bfd_link_hash_table_create \
	elf_cris_link_hash_table_create
#define elf_backend_adjust_dynamic_symbol \
	elf_cris_adjust_dynamic_symbol
#define elf_backend_copy_indirect_symbol \
	elf_cris_copy_indirect_symbol
#define elf_backend_late_size_sections \
	elf_cris_late_size_sections
#define elf_backend_init_index_section		_bfd_elf_init_1_index_section
#define elf_backend_finish_dynamic_symbol \
	elf_cris_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections \
	elf_cris_finish_dynamic_sections
#define elf_backend_create_dynamic_sections \
	_bfd_elf_create_dynamic_sections
#define bfd_elf32_bfd_final_link \
	bfd_elf_gc_common_final_link
#define elf_backend_hide_symbol			elf_cris_hide_symbol
#define elf_backend_reloc_type_class		elf_cris_reloc_type_class

#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_want_plt_sym	0
#define elf_backend_got_header_size	12
#define elf_backend_got_elt_size elf_cris_got_elt_size
#define elf_backend_dtrel_excludes_plt	1
#define elf_backend_want_dynrelro	1

#define elf_backend_default_execstack	0

/* Later, we my want to optimize RELA entries into REL entries for dynamic
   linking and libraries (if it's a win of any significance).  Until then,
   take the easy route.  */
#define elf_backend_may_use_rel_p 0
#define elf_backend_may_use_rela_p 1
#define elf_backend_rela_normal		1

#define elf_backend_linux_prpsinfo32_ugid16	true

#include "elf32-target.h"

#undef TARGET_LITTLE_SYM
#undef TARGET_LITTLE_NAME
#undef elf_symbol_leading_char

#define TARGET_LITTLE_SYM cris_elf32_us_vec
#define TARGET_LITTLE_NAME "elf32-us-cris"
#define elf_symbol_leading_char '_'
#undef elf32_bed
#define elf32_bed elf32_us_cris_bed

#include "elf32-target.h"
