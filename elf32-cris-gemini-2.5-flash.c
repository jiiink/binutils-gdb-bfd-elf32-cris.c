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

static const reloc_howto_type *
cris_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
			bfd_reloc_code_real_type code)
{
  size_t i;

  for (i = 0; i < sizeof (cris_reloc_map) / sizeof (cris_reloc_map[0]); ++i)
    {
      if (cris_reloc_map[i].bfd_reloc_val == code)
        {
          return &cris_elf_howto_table[cris_reloc_map[i].cris_reloc_val];
        }
    }

  return NULL;
}

static reloc_howto_type *
cris_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  if (r_name == NULL)
    {
      return NULL;
    }

  const size_t table_size = sizeof (cris_elf_howto_table) / sizeof (cris_elf_howto_table[0]);
  size_t i;

  for (i = 0; i < table_size; ++i)
    {
      if (cris_elf_howto_table[i].name != NULL
	  && strcasecmp (cris_elf_howto_table[i].name, r_name) == 0)
	{
	  return &cris_elf_howto_table[i];
	}
    }

  return NULL;
}

/* Set the howto pointer for an CRIS ELF reloc.  */

static bool
cris_info_to_howto_rela (bfd * abfd ATTRIBUTE_UNUSED,
                         arelent * cache_ptr,
                         Elf_Internal_Rela * dst)
{
  enum elf_cris_reloc_type r_type;

  if (cache_ptr == NULL)
    {
      _bfd_error_handler (_("%pB: Internal error: relocation cache pointer is NULL"), abfd);
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }
  if (dst == NULL)
    {
      _bfd_error_handler (_("%pB: Internal error: relocation data pointer is NULL"), abfd);
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  r_type = ELF32_R_TYPE (dst->r_info);
  if (r_type >= R_CRIS_max)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
                          abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  cache_ptr->howto = & cris_elf_howto_table [r_type];
  return true;
}

bfd_reloc_status_type
cris_elf_pcrel_reloc (bfd *abfd ATTRIBUTE_UNUSED,
		      arelent *reloc_entry,
		      asymbol *symbol,
		      void * data ATTRIBUTE_UNUSED,
		      asection *input_section,
		      bfd *output_bfd,
		      char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd == NULL)
    {
      reloc_entry->addend -= bfd_get_reloc_size (reloc_entry->howto);
    }

  return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
			        input_section, output_bfd, error_message);
}

/* Support for core dump NOTE sections.
   The slightly unintuitive code layout is an attempt to keep at least
   some similarities with other ports, hoping to simplify general
   changes, while still keeping Linux/CRIS and Linux/CRISv32 code apart.  */

static const int PR_CURSIG_OFFSET = 12;
static const int PR_PID_OFFSET = 22;
static const int PR_REG_COMMON_OFFSET = 70;

static const int CRIS_V32_PRSTATUS_TOTAL_SIZE = 202;
static const int CRIS_V32_PR_REG_SIZE = 128;

static const int CRIS_GENERIC_PRSTATUS_TOTAL_SIZE = 214;
static const int CRIS_GENERIC_PR_REG_SIZE = 140;

static bool
cris_elf_grok_prstatus(bfd *abfd, Elf_Internal_Note *note)
{
    size_t reg_size;
    bfd_machine_enum machine = bfd_get_mach(abfd);
    CORE_ADDR reg_file_offset;

    if (note->descsz < PR_PID_OFFSET + sizeof(uint32_t)) {
        return false;
    }

    elf_tdata(abfd)->core->signal = bfd_get_16(abfd, note->descdata + PR_CURSIG_OFFSET);
    elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, note->descdata + PR_PID_OFFSET);

    if (machine == bfd_mach_cris_v32) {
        if (note->descsz != CRIS_V32_PRSTATUS_TOTAL_SIZE) {
            return false;
        }
        reg_size = CRIS_V32_PR_REG_SIZE;
    } else {
        if (note->descsz != CRIS_GENERIC_PRSTATUS_TOTAL_SIZE) {
            return false;
        }
        reg_size = CRIS_GENERIC_PR_REG_SIZE;
    }

    if (PR_REG_COMMON_OFFSET + reg_size > note->descsz) {
        return false;
    }

    reg_file_offset = note->descpos + PR_REG_COMMON_OFFSET;

    return _bfd_elfcore_make_pseudosection(abfd, ".reg", reg_size, reg_file_offset);
}

static bool
cris_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  /* The original code had identical logic for note->descsz == 124
     regardless of the machine type (bfd_mach_cris_v32 or other).
     The machine type check was only relevant for the comments.
     Consolidate the check for descsz first.
     If descsz is not 124, both original branches returned false. */
  if (note->descsz != 124)
    {
      return false;
    }

  /* Linux/CRIS elf_prpsinfo or Linux/CRISv32 elf_prpsinfo.
     Add NULL checks for improved reliability: _bfd_elfcore_strndup can fail. */
  elf_tdata (abfd)->core->program
    = _bfd_elfcore_strndup (abfd, note->descdata + 28, 16);
  if (elf_tdata (abfd)->core->program == NULL)
    {
      /* Failed to allocate or copy program string. */
      return false;
    }

  elf_tdata (abfd)->core->command
    = _bfd_elfcore_strndup (abfd, note->descdata + 44, 80);
  if (elf_tdata (abfd)->core->command == NULL)
    {
      /* Failed to allocate or copy command string.
         The original code did not provide cleanup for program in this case.
         Following that behavior, but ensuring no NULL dereference. */
      return false;
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */
  char *command = elf_tdata (abfd)->core->command;
  int n = strlen (command);

  if (0 < n && command[n - 1] == ' ')
    {
      command[n - 1] = '\0';
    }

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
elf_cris_link_hash_newfunc (struct bfd_hash_entry *entry,
			    struct bfd_hash_table *table,
			    const char *string)
{
  struct elf_cris_link_hash_entry *ret = (struct elf_cris_link_hash_entry *) entry;

  if (!ret)
    {
      ret = (struct elf_cris_link_hash_entry *)
            bfd_hash_allocate (table, sizeof (struct elf_cris_link_hash_entry));
      if (!ret)
        return NULL;
    }

  ret = (struct elf_cris_link_hash_entry *)
        _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret, table, string);

  if (ret)
    {
      ret->pcrel_relocs_copied = NULL;
      ret->gotplt_refcount = 0;
      ret->gotplt_offset = 0;
      ret->dtp_refcount = 0;
      ret->tprel_refcount = 0;
      ret->reg_got_refcount = 0;
    }

  return (struct bfd_hash_entry *) ret;
}

/* Create a CRIS ELF linker hash table.  */

static const unsigned int CRIS_GOTPLT_INITIAL_OFFSET_BYTES = 12;

static struct bfd_link_hash_table *
elf_cris_link_hash_table_create (bfd *abfd)
{
  struct elf_cris_link_hash_table *ret = bfd_zmalloc (sizeof (struct elf_cris_link_hash_table));
  if (!ret)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
				      elf_cris_link_hash_newfunc,
				      sizeof (struct elf_cris_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  ret->next_gotplt_entry = CRIS_GOTPLT_INITIAL_OFFSET_BYTES;

  return &ret->root.root;
}

/* Perform a single relocation.  By default we use the standard BFD
   routines, with a few tweaks.  */

static bfd_reloc_status_type
cris_final_link_relocate (reloc_howto_type *  howto,
			  bfd *		      input_bfd,
			  asection *	      input_section,
			  bfd_byte *	      contents,
			  Elf_Internal_Rela * rel,
			  bfd_vma	      relocation)
{
  enum elf_cris_reloc_type r_type = ELF32_R_TYPE (rel->r_info);

  switch (r_type)
    {
    case R_CRIS_16_GOTPLT:
    case R_CRIS_16_GOT:
      if ((bfd_signed_vma) relocation < 0)
	return bfd_reloc_overflow;
      break;

    case R_CRIS_32_PLT_PCREL:
    case R_CRIS_32_PCREL:
      relocation -= 4;
      break;

    case R_CRIS_8_PCREL:
    case R_CRIS_16_PCREL:
      relocation -= 2;
      break;

    default:
      break;
    }

  return _bfd_final_link_relocate (howto, input_bfd, input_section,
				contents, rel->r_offset,
				relocation, rel->r_addend);
}


/* The number of errors left before we stop outputting reloc-specific
   explanatory messages.  By coincidence, this works nicely together
   with the default number of messages you'll get from LD about
   "relocation truncated to fit" messages before you get an
   "additional relocation overflows omitted from the output".  */
static int additional_relocation_error_msg_count = 10;

/* Relocate an CRIS ELF section.  See elf32-fr30.c, from where this was
   copied, for further comments.  */

static bool
cris_elf_report_error (struct bfd_link_info *info, bfd *input_bfd,
                       asection *input_section, const char *symbol_name,
                       const char *reloc_name, int64_t addend_val, const char *msg_fmt)
{
  const char *name_to_display = (symbol_name != NULL && symbol_name[0] != '\0'
                                 ? symbol_name : _("[whose name is lost]"));
  if (addend_val != 0)
    _bfd_error_handler (msg_fmt, input_bfd, input_section, reloc_name,
                        addend_val, name_to_display);
  else
    _bfd_error_handler (msg_fmt, input_bfd, input_section, reloc_name,
                        name_to_display);

  bfd_set_error (bfd_error_bad_value);
  return false;
}

static void
cris_elf_report_reloc_overflow (struct bfd_link_info *info,
                                struct bfd_link_hash_entry *h,
                                const char *symname, const char *howto_name,
                                bfd *input_bfd, asection *input_section,
                                bfd_vma offset, enum elf_cris_reloc_type r_type)
{
  (*info->callbacks->reloc_overflow)
    (info, (h ? &h->root : NULL), symname, howto_name,
     (bfd_vma) 0, input_bfd, input_section, offset);

  if (additional_relocation_error_msg_count > 0)
    {
      additional_relocation_error_msg_count--;
      switch (r_type)
        {
        case R_CRIS_16_GOTPLT:
        case R_CRIS_16_GOT:
        case R_CRIS_16_GOT_TPREL:
        case R_CRIS_16_GOT_GD:
          _bfd_error_handler (_("(too many global variables for -fpic:"
                               " recompile with -fPIC)"));
          break;

        case R_CRIS_16_TPREL:
        case R_CRIS_16_DTPREL:
          _bfd_error_handler (_("(thread-local data too big for -fpic or"
                               " -msmall-tls: recompile with -fPIC or"
                               " -mno-small-tls)"));
          break;

        default:
          break;
        }
    }
}

static bool
cris_elf_handle_got_plt_reloc (struct bfd_link_info *info,
                               bfd *input_bfd, asection *input_section,
                               Elf_Internal_Rela *rel,
                               enum elf_cris_reloc_type r_type,
                               struct elf_link_hash_entry *h,
                               const char *symname,
                               struct elf_cris_link_hash_table *htab,
                               bfd_vma *relocation)
{
  if (h != NULL && ((struct elf_cris_link_hash_entry *) h)->gotplt_offset != 0)
    {
      asection *sgotplt = htab->root.sgotplt;
      BFD_ASSERT (h->dynindx != -1);
      BFD_ASSERT (sgotplt != NULL);

      *relocation = ((struct elf_cris_link_hash_entry *) h)->gotplt_offset;
      return true; // Relocation handled, break from switch
    }

  // Fall-through logic for cases where PLT entry is not made or needed for a specific reason.
  // This section validates if falling through to GOT is appropriate or if it's an error.
  if (h != NULL
      && (h->got.offset == (bfd_vma) -1
          || (!bfd_link_pic (info)
              && !(h->def_regular
                   || (!h->def_dynamic
                       && h->root.type == bfd_link_hash_undefweak)))))
    {
      _bfd_error_handler
        ((h->got.offset == (bfd_vma) -1)
         ? _("%pB, section %pA: no PLT nor GOT for relocation %s"
             " against symbol `%s'")
         : _("%pB, section %pA: no PLT for relocation %s"
             " against symbol `%s'"),
         input_bfd,
         input_section,
         cris_elf_howto_table[r_type].name,
         symname != NULL && symname[0] != '\0' ? symname : _("[whose name is lost]"));
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  return true; // Proceed to GOT handling (fall-through) or regular processing
}

static bool
cris_elf_handle_got_reloc (bfd *output_bfd,
                           struct bfd_link_info *info,
                           bfd *input_bfd, asection *input_section,
                           Elf_Internal_Rela *rel,
                           enum elf_cris_reloc_type r_type,
                           struct elf_link_hash_entry *h,
                           const char *symname,
                           struct elf_cris_link_hash_table *htab,
                           bfd_vma *local_got_offsets,
                           asection *sgot, asection **srelgot_ptr,
                           unsigned long r_symndx, bfd_vma *relocation)
{
  bfd_vma off;
  bool got_entry_initialized = false;

  if (h != NULL)
    {
      off = h->got.offset;
      BFD_ASSERT (off != (bfd_vma) -1);

      if (!elf_hash_table (info)->dynamic_sections_created
          || (! bfd_link_pic (info)
              && (h->def_regular
                  || h->type == STT_FUNC
                  || h->needs_plt))
          || (bfd_link_pic (info)
              && (SYMBOLIC_BIND (info, h) || h->dynindx == -1)
              && h->def_regular))
        {
          BFD_ASSERT (!elf_hash_table (info)->dynamic_sections_created
                      || bfd_link_pic (info)
                      || h->def_regular
                      || h->type == STT_FUNC
                      || h->needs_plt
                      || h->root.type == bfd_link_hash_undefweak);

          if ((off & 1) == 0) // If not yet initialized
            {
              bfd_put_32 (output_bfd, *relocation, sgot->contents + (off & ~1));
              h->got.offset |= 1;
            }
          got_entry_initialized = true;
        }
    }
  else
    {
      BFD_ASSERT (local_got_offsets != NULL
                  && local_got_offsets[r_symndx] != (bfd_vma) -1);

      off = local_got_offsets[r_symndx];

      if ((off & 1) == 0) // If not yet initialized
        {
          bfd_put_32 (output_bfd, *relocation, sgot->contents + (off & ~1));

          if (bfd_link_pic (info))
            {
              Elf_Internal_Rela outrel;
              bfd_byte *loc;

              *srelgot_ptr = htab->root.srelgot;
              BFD_ASSERT (*srelgot_ptr != NULL);

              outrel.r_offset = (sgot->output_section->vma
                                 + sgot->output_offset
                                 + (off & ~1));
              outrel.r_info = ELF32_R_INFO (0, R_CRIS_RELATIVE);
              outrel.r_addend = *relocation;
              loc = (*srelgot_ptr)->contents;
              loc += (*srelgot_ptr)->reloc_count++ * sizeof (Elf32_External_Rela);
              bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
            }
          local_got_offsets[r_symndx] |= 1;
        }
      got_entry_initialized = true;
    }

  if (got_entry_initialized)
    *relocation = sgot->output_offset + (off & ~1); // Update relocation with true GOT entry address

  if (rel->r_addend != 0)
    {
      return cris_elf_report_error (info, input_bfd, input_section, symname,
                                    cris_elf_howto_table[r_type].name,
                                    rel->r_addend,
                                    _("%pB, section %pA: relocation %s with non-zero addend"
                                      " %" PRId64 " against symbol `%s'"));
    }
  return true;
}

static bool
cris_elf_handle_gotrel_reloc (struct bfd_link_info *info,
                              bfd *input_bfd, asection *input_section,
                              enum elf_cris_reloc_type r_type,
                              struct elf_link_hash_entry *h,
                              const char *symname, asection *sgot,
                              bfd_vma *relocation)
{
  if (h != NULL
      && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
      && !(!bfd_link_pic (info)
           && (h->def_regular
               || (!h->def_dynamic
                   && h->root.type == bfd_link_hash_undefweak))))
    {
      _bfd_error_handler
        (_("%pB, section %pA: relocation %s is"
           " not allowed for global symbol: `%s'"),
         input_bfd,
         input_section,
         cris_elf_howto_table[r_type].name,
         symname);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  if (sgot == NULL)
    {
      _bfd_error_handler
        (_("%pB, section %pA: relocation %s with no GOT created"),
         input_bfd,
         input_section,
         cris_elf_howto_table[r_type].name);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  *relocation -= sgot->output_section->vma;
  return true;
}

static bool
cris_elf_handle_plt_reloc (struct bfd_link_info *info,
                           struct elf_link_hash_entry *h,
                           asection *splt, asection *sgot,
                           enum elf_cris_reloc_type r_type,
                           bfd_vma *relocation)
{
  // If local symbol or no PLT entry, no specific PLT handling,
  // relocation remains as computed for symbol's value.
  if (h == NULL || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
      || h->plt.offset == (bfd_vma) -1 || splt == NULL)
    return true;

  *relocation = (splt->output_section->vma
                 + splt->output_offset
                 + h->plt.offset);

  if (r_type == R_CRIS_32_PLT_GOTREL)
    *relocation -= sgot->output_section->vma;

  return true;
}

static bool
cris_elf_write_dynamic_rela (bfd *output_bfd, asection *target_srel,
                             bfd_vma r_offset, unsigned long r_info_sym,
                             enum elf_cris_reloc_type r_info_type,
                             bfd_vma r_addend)
{
  Elf_Internal_Rela outrel;
  bfd_byte *loc;

  BFD_ASSERT (target_srel != NULL);
  if (target_srel == NULL || target_srel->contents == NULL)
    {
      bfd_set_error (bfd_error_no_memory);
      return false;
    }

  outrel.r_offset = r_offset;
  outrel.r_info = ELF32_R_INFO (r_info_sym, r_info_type);
  outrel.r_addend = r_addend;

  loc = target_srel->contents;
  loc += target_srel->reloc_count++ * sizeof (Elf32_External_Rela);
  bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
  return true;
}

static bool
cris_elf_handle_dynamic_copy_reloc (bfd *output_bfd,
                                    struct bfd_link_info *info,
                                    bfd *input_bfd,
                                    asection *input_section,
                                    Elf_Internal_Rela *rel,
                                    enum elf_cris_reloc_type r_type,
                                    unsigned long r_symndx,
                                    struct elf_link_hash_entry *h,
                                    asection *sec,
                                    struct elf_cris_link_hash_table *htab,
                                    asection **sreloc_ptr,
                                    bfd_vma *relocation,
                                    bool *out_skip_final_relocate)
{
  *out_skip_final_relocate = false;

  bool should_copy_to_dynrel_cond =
    (bfd_link_pic (info)
     && r_symndx != STN_UNDEF
     && (input_section->flags & SEC_ALLOC) != 0
     && ((r_type != R_CRIS_8_PCREL
          && r_type != R_CRIS_16_PCREL
          && r_type != R_CRIS_32_PCREL)
         || (!SYMBOLIC_BIND (info, h)
             || (h != NULL && !h->def_regular))));

  if (!should_copy_to_dynrel_cond)
    return true; // No dynamic copy needed, proceed with normal relocation

  if (*sreloc_ptr == NULL)
    {
      *sreloc_ptr = _bfd_elf_get_dynamic_reloc_section
        (htab->root.dynobj, input_section, /*rela?*/ true);
      if (*sreloc_ptr == NULL)
        {
          bfd_set_error (bfd_error_bad_value);
          return false;
        }
    }

  bfd_vma outrel_offset = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);
  bool is_skip_dynamic_reloc_creation = false;
  bool do_actual_relocate_now = false;

  if (outrel_offset == (bfd_vma) -1)
    is_skip_dynamic_reloc_creation = true;
  else if (outrel_offset == (bfd_vma) -2
           || (h != NULL && h->root.type == bfd_link_hash_undefweak && ELF_ST_VISIBILITY (h->other) != STV_DEFAULT))
    {
      is_skip_dynamic_reloc_creation = true;
      do_actual_relocate_now = true;
    }

  if (!is_skip_dynamic_reloc_creation)
    {
      outrel_offset += (input_section->output_section->vma + input_section->output_offset);

      unsigned long r_info_sym_dyn = 0;
      enum elf_cris_reloc_type r_info_type_dyn = r_type;
      bfd_vma r_addend_dyn = *relocation + rel->r_addend;

      if (h != NULL && ((!SYMBOLIC_BIND (info, h) && h->dynindx != -1) || !h->def_regular))
        {
          BFD_ASSERT (h->dynindx != -1);
          r_info_sym_dyn = h->dynindx;
        }
      else
        {
          if (r_type == R_CRIS_32)
            {
              do_actual_relocate_now = true;
              r_info_type_dyn = R_CRIS_RELATIVE;
            }
          else
            {
              long indx;
              if (bfd_is_abs_section (sec))
                indx = 0;
              else if (sec == NULL || sec->owner == NULL)
                {
                  bfd_set_error (bfd_error_bad_value);
                  return false;
                }
              else
                {
                  asection *osec = sec->output_section;
                  indx = elf_section_data (osec)->dynindx;
                  if (indx == 0)
                    {
                      osec = htab->root.text_index_section;
                      indx = elf_section_data (osec)->dynindx;
                    }
                  BFD_ASSERT (indx != 0);
                }
              r_info_sym_dyn = indx;
            }
        }

      if (!cris_elf_write_dynamic_rela (output_bfd, *sreloc_ptr, outrel_offset,
                                        r_info_sym_dyn, r_info_type_dyn, r_addend_dyn))
        return false;
    }

  *out_skip_final_relocate = !do_actual_relocate_now;
  return true;
}

static bool
cris_elf_handle_dtprel_reloc (bfd *output_bfd,
                              struct bfd_link_info *info,
                              bfd *input_bfd, asection *input_section,
                              Elf_Internal_Rela *rel,
                              enum elf_cris_reloc_type r_type,
                              struct elf_link_hash_entry *h,
                              const char *symname,
                              struct elf_cris_link_hash_table *htab,
                              asection **srelgot_ptr,
                              bfd_vma *relocation)
{
  if (h != NULL
      && (input_section->flags & SEC_ALLOC) != 0
      && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
      && (bfd_link_pic (info)
          || (!h->def_regular
              && h->root.type != bfd_link_hash_undefined)))
    {
      _bfd_error_handler
        ((h->root.type == bfd_link_hash_undefined)
         ? _("%pB, section %pA: relocation %s has an undefined"
             " reference to `%s', perhaps a declaration mixup?")
         : _("%pB, section %pA: relocation %s is"
             " not allowed for `%s', a global symbol with default"
             " visibility, perhaps a declaration mixup?"),
         input_bfd,
         input_section,
         cris_elf_howto_table[r_type].name,
         symname != NULL && symname[0] != '\0' ? symname : _("[whose name is lost]"));
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  BFD_ASSERT ((input_section->flags & SEC_ALLOC) == 0
              || htab->dtpmod_refcount != 0);

  if (htab->dtpmod_refcount > 0 && (input_section->flags & SEC_ALLOC) != 0)
    {
      asection *sgotplt = htab->root.sgotplt;
      BFD_ASSERT (sgotplt != NULL);

      if (bfd_link_pic (info))
        {
          *srelgot_ptr = htab->root.srelgot;
          BFD_ASSERT (*srelgot_ptr != NULL);

          bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 12);
          bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 16);

          if (!cris_elf_write_dynamic_rela (output_bfd, *srelgot_ptr,
                                            sgotplt->output_section->vma + sgotplt->output_offset + 12,
                                            0, R_CRIS_DTPMOD, 0))
            return false;
        }
      else
        {
          bfd_put_32 (output_bfd, (bfd_vma) 1, sgotplt->contents + 12);
          bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 16);
        }
      htab->dtpmod_refcount = - htab->dtpmod_refcount;
    }

  *relocation -= elf_hash_table (info)->tls_sec == NULL
    ? 0 : elf_hash_table (info)->tls_sec->vma;
  return true;
}

static bool
cris_elf_handle_gd_ie_reloc (bfd *output_bfd,
                             struct bfd_link_info *info,
                             bfd *input_bfd, asection *input_section,
                             Elf_Internal_Rela *rel,
                             enum elf_cris_reloc_type r_type,
                             unsigned long r_symndx,
                             struct elf_link_hash_entry *h,
                             const char *symname,
                             struct elf_cris_link_hash_table *htab,
                             bfd_vma *local_got_offsets,
                             asection *sgot, asection **srelgot_ptr,
                             bfd_vma *relocation)
{
  if (r_type == R_CRIS_32_GD || r_type == R_CRIS_32_IE)
    {
      if (bfd_link_pic (info))
        {
          bfd_set_error (bfd_error_invalid_operation);
          return false;
        }
    }

  if (rel->r_addend != 0)
    {
      return cris_elf_report_error (info, input_bfd, input_section, symname,
                                    cris_elf_howto_table[r_type].name,
                                    rel->r_addend,
                                    _("%pB, section %pA: relocation %s with non-zero addend"
                                      " %" PRId64 " against symbol `%s'"));
    }

  bfd_vma off;
  int bit_flag = (r_type == R_CRIS_32_IE || r_type == R_CRIS_16_GOT_TPREL || r_type == R_CRIS_32_GOT_TPREL) ? 1 : 2;

  if (!bfd_link_pic (info)
      && (h == NULL || h->def_regular || ELF_COMMON_DEF_P (h)))
    {
      if (h != NULL)
        {
          off = elf_cris_hash_entry (h)->tprel_refcount > 0 ? h->got.offset + 4 : h->got.offset;
        }
      else
        {
          off = local_got_offsets[r_symndx];
          if (LGOT_TPREL_NDX (r_symndx) < (bfd_vma) (~0UL / sizeof (bfd_vma)) && local_got_offsets[LGOT_TPREL_NDX (r_symndx)])
            off += 4;
        }

      if ((off & bit_flag) == 0)
        {
          off &= ~3;

          if (h != NULL)
            h->got.offset |= bit_flag;
          else
            local_got_offsets[r_symndx] |= bit_flag;

          if (bit_flag == 2) // R_CRIS_GD related
            {
              *relocation -= elf_hash_table (info)->tls_sec->vma;
              bfd_put_32 (output_bfd, 1, sgot->contents + off);
              bfd_put_32 (output_bfd, *relocation, sgot->contents + off + 4);
            }
          else // R_CRIS_IE related
            {
              *relocation -= elf_hash_table (info)->tls_sec->vma;
              *relocation -= elf_hash_table (info)->tls_size;
              bfd_put_32 (output_bfd, *relocation, sgot->contents + off);
            }
        }
      else
        off &= ~3;

      *relocation = sgot->output_offset + off
        + ((r_type == R_CRIS_32_GD || r_type == R_CRIS_32_IE) ? sgot->output_section->vma : 0);
    }
  else
    {
      if (h != NULL)
        {
          off = elf_cris_hash_entry (h)->tprel_refcount > 0 ? h->got.offset + 4 : h->got.offset;
        }
      else
        {
          off = local_got_offsets[r_symndx];
          if (LGOT_TPREL_NDX (r_symndx) < (bfd_vma) (~0UL / sizeof (bfd_vma)) && local_got_offsets[LGOT_TPREL_NDX (r_symndx)])
            off += 4;
        }

      if ((off & bit_flag) == 0)
        {
          off &= ~3;

          if (h != NULL)
            h->got.offset |= bit_flag;
          else
            local_got_offsets[r_symndx] |= bit_flag;

          *srelgot_ptr = htab->root.srelgot;
          BFD_ASSERT (*srelgot_ptr != NULL);

          unsigned long r_info_sym_dyn = 0;
          enum elf_cris_reloc_type r_info_type_dyn = 0;
          bfd_vma r_addend_dyn = 0;

          if (bit_flag == 2) // R_CRIS_GD related
            {
              bfd_put_32 (output_bfd, 0, sgot->contents + off);
              bfd_put_32 (output_bfd, 0, sgot->contents + off + 4);

              if (h != NULL && h->dynindx != -1)
                {
                  r_info_sym_dyn = h->dynindx;
                  r_info_type_dyn = R_CRIS_DTP;
                  r_addend_dyn = 0;
                }
              else
                {
                  r_info_type_dyn = R_CRIS_DTP;
                  r_addend_dyn = *relocation - (elf_hash_table (info)->tls_sec == NULL ? 0 : elf_hash_table (info)->tls_sec->vma);
                }

              if (!cris_elf_write_dynamic_rela (output_bfd, *srelgot_ptr,
                                                sgot->output_section->vma + sgot->output_offset + off,
                                                r_info_sym_dyn, r_info_type_dyn, r_addend_dyn))
                return false;
            }
          else // R_CRIS_IE related
            {
              if (h != NULL && h->dynindx != -1)
                {
                  r_info_sym_dyn = h->dynindx;
                  r_info_type_dyn = R_CRIS_32_TPREL;
                  r_addend_dyn = 0;
                }
              else
                {
                  r_info_type_dyn = R_CRIS_32_TPREL;
                  r_addend_dyn = *relocation - (elf_hash_table (info)->tls_sec == NULL ? 0 : elf_hash_table (info)->tls_sec->vma);
                }

              bfd_put_32 (output_bfd, r_addend_dyn, sgot->contents + off);

              if (!cris_elf_write_dynamic_rela (output_bfd, *srelgot_ptr,
                                                sgot->output_section->vma + sgot->output_offset + off,
                                                r_info_sym_dyn, r_info_type_dyn, r_addend_dyn))
                return false;
            }
        }
      else
        off &= ~3;

      *relocation = sgot->output_offset + off
        + ((r_type == R_CRIS_32_GD || r_type == R_CRIS_32_IE) ? sgot->output_section->vma : 0);
    }
  return true;
}

static bool
cris_elf_handle_tprel_reloc (struct bfd_link_info *info,
                             bfd *input_bfd, asection *input_section,
                             enum elf_cris_reloc_type r_type,
                             struct elf_link_hash_entry *h,
                             const char *symname,
                             bfd_vma *relocation)
{
  if (bfd_link_pic (info))
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  if (h != NULL
      && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
      && !(h->def_regular || ELF_COMMON_DEF_P (h))
      && h->root.type != bfd_link_hash_undefined)
    {
      _bfd_error_handler
        (_("%pB, section %pA: relocation %s is"
           " not allowed for symbol: `%s'"
           " which is defined outside the program,"
           " perhaps a declaration mixup?"),
         input_bfd,
         input_section,
         cris_elf_howto_table[r_type].name,
         symname);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  *relocation -= elf_hash_table (info)->tls_sec == NULL
    ? 0
    : (elf_hash_table (info)->tls_sec->vma
       + elf_hash_table (info)->tls_size);
  return true;
}

static int
cris_elf_relocate_section (bfd *output_bfd,
			   struct bfd_link_info *info,
			   bfd *input_bfd,
			   asection *input_section,
			   bfd_byte *contents,
			   Elf_Internal_Rela *relocs,
			   Elf_Internal_Sym *local_syms,
			   asection **local_sections)
{
  struct elf_cris_link_hash_table *htab;
  bfd *dynobj;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma *local_got_offsets;
  asection *sgot;
  asection *splt;
  asection *sreloc_local = NULL;
  asection *srelgot_local = NULL;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;

  htab = elf_cris_hash_table (info);
  if (htab == NULL)
    return false;

  dynobj = htab->root.dynobj;
  local_got_offsets = elf_local_got_offsets (input_bfd);
  symtab_hdr = & elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);
  relend     = relocs + input_section->reloc_count;

  sgot = NULL;
  splt = NULL;

  if (dynobj != NULL)
    {
      splt = htab->root.splt;
      sgot = htab->root.sgot;
    }

  for (rel = relocs; rel < relend; rel ++)
    {
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      struct elf_link_hash_entry *h = NULL;
      bfd_vma relocation;
      enum elf_cris_reloc_type r_type;
      bool resolved_to_zero;
      const char *symname = NULL;

      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type == R_CRIS_GNU_VTINHERIT || r_type == R_CRIS_GNU_VTENTRY)
	continue;

      r_symndx = ELF32_R_SYM (rel->r_info);
      howto  = cris_elf_howto_table + r_type;

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections [r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);

	  symname = (bfd_elf_string_from_elf_section
		     (input_bfd, symtab_hdr->sh_link, sym->st_name));
	  if (symname == NULL || symname[0] == '\0')
	    symname = bfd_section_name (sec);
	}
      else
	{
	  bool warned, ignored;
	  bool unresolved_reloc;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);

	  symname = h->root.root.string;

	  if (unresolved_reloc
	      && sec != NULL && (sec->owner->flags & DYNAMIC) != 0)
	    relocation = 0;
	  else if (h != NULL && (h->root.type == bfd_link_hash_defined
		   || h->root.type == bfd_link_hash_defweak))
	    {
	      if (bfd_link_pic (info)
		  && ((!SYMBOLIC_BIND (info, h) && h->dynindx != -1)
		      || !h->def_regular)
		  && (input_section->flags & SEC_ALLOC) != 0
		  && (r_type == R_CRIS_8
		      || r_type == R_CRIS_16
		      || r_type == R_CRIS_32
		      || r_type == R_CRIS_8_PCREL
		      || r_type == R_CRIS_16_PCREL
		      || r_type == R_CRIS_32_PCREL))
		relocation = 0;
	      else if (!bfd_link_relocatable (info) && unresolved_reloc
		       && (_bfd_elf_section_offset (output_bfd, info,
						    input_section,
						    rel->r_offset)
			   != (bfd_vma) -1))
		{
		  _bfd_error_handler
		    (_("%pB, section %pA: unresolvable relocation %s against symbol `%s'"),
		     input_bfd,
		     input_section,
		     cris_elf_howto_table[r_type].name,
		     symname);
		  bfd_set_error (bfd_error_bad_value);
		  return false;
		}
	    }
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_CRIS_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      resolved_to_zero = (h != NULL && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

      bool result_ok = true;
      bool skip_final_relocate = false;

      switch (r_type)
	{
	case R_CRIS_16_GOTPLT:
	case R_CRIS_32_GOTPLT:
	  result_ok = cris_elf_handle_got_plt_reloc (info, input_bfd,
                                                     input_section, rel, r_type, h,
                                                     symname, htab, &relocation);
	  if (!result_ok) return false;
	  // If PLT-specific handling happened, break, else fall-through to GOT
	  if (h != NULL && ((struct elf_cris_link_hash_entry *) h)->gotplt_offset != 0)
	    break;
	  /* Fall through */

	case R_CRIS_16_GOT:
	case R_CRIS_32_GOT:
	  result_ok = cris_elf_handle_got_reloc (output_bfd, info, input_bfd,
                                                 input_section, rel, r_type, h, symname,
                                                 htab, local_got_offsets, sgot,
                                                 &srelgot_local, r_symndx, &relocation);
	  if (!result_ok) return false;
	  break;

	case R_CRIS_32_GOTREL:
	  result_ok = cris_elf_handle_gotrel_reloc (info, input_bfd, input_section,
                                                    r_type, h, symname, sgot, &relocation);
	  if (!result_ok) return false;
	  break;

	case R_CRIS_32_PLT_PCREL:
	case R_CRIS_32_PLT_GOTREL:
	  result_ok = cris_elf_handle_plt_reloc (info, h, splt, sgot, r_type, &relocation);
	  if (!result_ok) return false;
	  break;

	case R_CRIS_8_PCREL:
	case R_CRIS_16_PCREL:
	case R_CRIS_32_PCREL:
	  if (h == NULL || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT || h->dynindx == -1)
	    break;
	  /* Fall through */
	case R_CRIS_8:
	case R_CRIS_16:
	case R_CRIS_32:
	  if (bfd_link_pic (info)
	      && !resolved_to_zero
	      && r_symndx != STN_UNDEF
	      && (input_section->flags & SEC_ALLOC) != 0)
	    {
	      result_ok = cris_elf_handle_dynamic_copy_reloc (output_bfd, info, input_bfd,
                                                              input_section, rel, r_type,
                                                              r_symndx, h, sec, htab,
                                                              &sreloc_local, &relocation,
                                                              &skip_final_relocate);
	      if (!result_ok) return false;
	      if (skip_final_relocate) continue;
	    }
	  break;

	case R_CRIS_16_DTPREL:
	case R_CRIS_32_DTPREL:
	  result_ok = cris_elf_handle_dtprel_reloc (output_bfd, info, input_bfd,
                                                    input_section, rel, r_type, h, symname,
                                                    htab, &srelgot_local, &relocation);
	  if (!result_ok) return false;
	  break;

	case R_CRIS_32_GD:
	case R_CRIS_16_GOT_GD:
	case R_CRIS_32_GOT_GD:
	case R_CRIS_32_IE:
	case R_CRIS_32_GOT_TPREL:
	case R_CRIS_16_GOT_TPREL:
	  result_ok = cris_elf_handle_gd_ie_reloc (output_bfd, info, input_bfd,
                                                   input_section, rel, r_type, r_symndx, h,
                                                   symname, htab, local_got_offsets,
                                                   sgot, &srelgot_local, &relocation);
	  if (!result_ok) return false;
	  break;

	case R_CRIS_16_TPREL:
	case R_CRIS_32_TPREL:
	  result_ok = cris_elf_handle_tprel_reloc (info, input_bfd, input_section,
                                                    r_type, h, symname, &relocation);
	  if (!result_ok) return false;
	  break;

	default:
	  BFD_FAIL ();
	  return false;
	}

      bfd_reloc_status_type r_status = cris_final_link_relocate (howto, input_bfd, input_section,
                                                                  contents, rel, relocation);

      if (r_status != bfd_reloc_ok)
	{
	  const char * msg = (const char *) NULL;

	  switch (r_status)
	    {
	    case bfd_reloc_overflow:
	      cris_elf_report_reloc_overflow (info, h, symname, howto->name,
                                              input_bfd, input_section, rel->r_offset, r_type);
	      break;

	    case bfd_reloc_undefined:
	      (*info->callbacks->undefined_symbol)
		(info, symname, input_bfd, input_section, rel->r_offset, true);
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
	    (*info->callbacks->warning) (info, msg, symname, input_bfd,
					 input_section, rel->r_offset);
	}
    }

  return true;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

#define CRIS_WORD_SIZE sizeof(bfd_vma)
#define CRIS_GOTPLT_FIXED_ENTRIES 3
#define CRIS_DTPMOD_RELOC_ADJUST 2
#define RELA_EXTERNAL_SIZE sizeof(Elf32_External_Rela)

typedef struct cris_plt_config
{
  int plt_off1;
  int plt_off2;
  int plt_off3;
  int plt_off3_value_bias;
  int plt_stub_offset;
  int plt_entry_size;
  const bfd_byte *plt_entry;
  const bfd_byte *plt_pic_entry;
} cris_plt_config;

static void
init_cris_plt_config (bfd *output_bfd, cris_plt_config *config)
{
  config->plt_off1 = 2;
  config->plt_off2 = 10;
  config->plt_off3 = 16;
  config->plt_off3_value_bias = 4;
  config->plt_stub_offset = 8;
  config->plt_entry_size = PLT_ENTRY_SIZE;
  config->plt_entry = elf_cris_plt_entry;
  config->plt_pic_entry = elf_cris_pic_plt_entry;

  if (bfd_get_mach (output_bfd) == bfd_mach_cris_v32)
    {
      config->plt_off2 = 14;
      config->plt_off3 = 20;
      config->plt_off3_value_bias = -2;
      config->plt_stub_offset = 12;
      config->plt_entry_size = PLT_ENTRY_SIZE_V32;
      config->plt_entry = elf_cris_plt_entry_v32;
      config->plt_pic_entry = elf_cris_pic_plt_entry_v32;
    }
}

static bool
handle_plt_entry (bfd *output_bfd, struct bfd_link_info *info,
                  struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                  struct elf_cris_link_hash_table *htab,
                  const cris_plt_config *plt_config)
{
  asection *splt = htab->root.splt;
  asection *sgotplt = htab->root.sgotplt;
  asection *srela = htab->root.srelplt;
  bfd_vma got_base;
  bfd_vma gotplt_offset = elf_cris_hash_entry (h)->gotplt_offset;
  bool has_gotplt = (gotplt_offset != 0);

  if (h->dynindx == (bfd_vma) -1)
    {
      bfd_set_error (_("dynamic index not set for PLT entry"));
      return false;
    }

  if (!splt || !sgotplt || (has_gotplt && !srela))
    {
      bfd_set_error (_("missing PLT related sections for dynamic symbol"));
      return false;
    }

  got_base = sgotplt->output_section->vma + sgotplt->output_offset;

  bfd_vma rela_plt_index = (gotplt_offset / CRIS_WORD_SIZE)
                           - CRIS_GOTPLT_FIXED_ENTRIES;
  if (htab->dtpmod_refcount != 0)
    rela_plt_index -= CRIS_DTPMOD_RELOC_ADJUST;

  bfd_vma got_offset = has_gotplt
                       ? gotplt_offset
                       : h->got.offset + htab->next_gotplt_entry;

  if (!bfd_link_pic (info))
    {
      memcpy (splt->contents + h->plt.offset, plt_config->plt_entry,
              plt_config->plt_entry_size);
      bfd_put_32 (output_bfd, got_base + got_offset,
                  splt->contents + h->plt.offset + plt_config->plt_off1);
    }
  else
    {
      memcpy (splt->contents + h->plt.offset, plt_config->plt_pic_entry,
              plt_config->plt_entry_size);
      bfd_put_32 (output_bfd, got_offset,
                  splt->contents + h->plt.offset + plt_config->plt_off1);
    }

  if (has_gotplt)
    {
      Elf_Internal_Rela rela;
      bfd_byte *rela_loc;

      bfd_put_32 (output_bfd,
                  rela_plt_index * RELA_EXTERNAL_SIZE,
                  splt->contents + h->plt.offset + plt_config->plt_off2);

      bfd_put_32 (output_bfd,
                  - (h->plt.offset + plt_config->plt_off3 + plt_config->plt_off3_value_bias),
                  splt->contents + h->plt.offset + plt_config->plt_off3);

      bfd_put_32 (output_bfd,
                  (splt->output_section->vma
                   + splt->output_offset
                   + h->plt.offset
                   + plt_config->plt_stub_offset),
                  sgotplt->contents + got_offset);

      rela.r_offset = (sgotplt->output_section->vma
                       + sgotplt->output_offset
                       + got_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_CRIS_JUMP_SLOT);
      rela.r_addend = 0;
      rela_loc = srela->contents + rela_plt_index * RELA_EXTERNAL_SIZE;
      bfd_elf32_swap_reloca_out (output_bfd, &rela, rela_loc);
    }

  if (!h->def_regular)
    {
      sym->st_shndx = SHN_UNDEF;
      if (!h->ref_regular_nonweak)
        sym->st_value = 0;
    }

  return true;
}

static bool
handle_got_entry (bfd *output_bfd, struct bfd_link_info *info,
                  struct elf_link_hash_entry *h,
                  struct elf_cris_link_hash_table *htab)
{
  asection *sgot = htab->root.sgot;
  asection *srela = htab->root.srelgot;
  Elf_Internal_Rela rela;
  bfd_byte *loc;
  bfd_byte *where;

  if (!sgot || !srela)
    {
      bfd_set_error (_("missing GOT related sections for dynamic symbol"));
      return false;
    }

  rela.r_offset = (sgot->output_section->vma
                   + sgot->output_offset
                   + (h->got.offset &~ (bfd_vma) 1));

  where = sgot->contents + (h->got.offset &~ (bfd_vma) 1);
  if (! elf_hash_table (info)->dynamic_sections_created
      || (bfd_link_pic (info)
          && (SYMBOLIC_BIND (info, h) || h->dynindx == (bfd_vma) -1)
          && h->def_regular))
    {
      rela.r_info = ELF32_R_INFO (0, R_CRIS_RELATIVE);
      rela.r_addend = bfd_get_signed_32 (output_bfd, where);
    }
  else
    {
      bfd_put_32 (output_bfd, (bfd_vma) 0, where);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_CRIS_GLOB_DAT);
      rela.r_addend = 0;
    }

  loc = srela->contents + srela->reloc_count++ * RELA_EXTERNAL_SIZE;
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

  return true;
}

static bool
handle_copy_relocation (bfd *output_bfd,
                        struct elf_link_hash_entry *h,
                        struct elf_cris_link_hash_table *htab)
{
  asection *srel;
  Elf_Internal_Rela rela;
  bfd_byte *loc;

  if (h->dynindx == (bfd_vma) -1
      || !(h->root.type == bfd_link_hash_defined
           || h->root.type == bfd_link_hash_defweak))
    {
      bfd_set_error (_("invalid hash entry for copy relocation"));
      return false;
    }

  if (h->root.u.def.section == htab->root.sdynrelro)
    srel = htab->root.sreldynrelro;
  else
    srel = htab->root.srelbss;

  if (!srel)
    {
      bfd_set_error (_("missing relocation section for copy relocation"));
      return false;
    }

  rela.r_offset = (h->root.u.def.value
                   + h->root.u.def.section->output_section->vma
                   + h->root.u.def.section->output_offset);
  rela.r_info = ELF32_R_INFO (h->dynindx, R_CRIS_COPY);
  rela.r_addend = 0;
  loc = srel->contents + srel->reloc_count++ * RELA_EXTERNAL_SIZE;
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

  return true;
}

static bool
elf_cris_finish_dynamic_symbol (bfd *output_bfd,
                                struct bfd_link_info *info,
                                struct elf_link_hash_entry *h,
                                Elf_Internal_Sym *sym)
{
  struct elf_cris_link_hash_table *htab = elf_cris_hash_table (info);
  cris_plt_config plt_config;

  init_cris_plt_config (output_bfd, &plt_config);

  if (h->plt.offset != (bfd_vma) -1)
    {
      if (!handle_plt_entry (output_bfd, info, h, sym, htab, &plt_config))
        return false;
    }

  if (h->got.offset != (bfd_vma) -1
      && elf_cris_hash_entry (h)->reg_got_refcount > 0
      && (bfd_link_pic (info)
          || (h->dynindx != (bfd_vma) -1
              && h->plt.offset == (bfd_vma) -1
              && !h->def_regular
              && h->root.type != bfd_link_hash_undefweak)))
    {
      if (!handle_got_entry (output_bfd, info, h, htab))
        return false;
    }

  if (h->needs_copy)
    {
      if (!handle_copy_relocation (output_bfd, h, htab))
        return false;
    }

  if (h == elf_hash_table (info)->hdynamic
      || h == elf_hash_table (info)->hgot)
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Finish up the dynamic sections.  Do *not* emit relocs here, as their
   offsets were changed, as part of -z combreloc handling, from those we
   computed.  */

static bool
elf_cris_finish_dynamic_sections (bfd *output_bfd,
				  struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sgot;
  asection *sdyn;
  struct elf_link_hash_table *ht;

  ht = elf_hash_table (info);
  BFD_ASSERT (ht != NULL);

  dynobj = ht->dynobj;

  sgot = ht->sgotplt;
  BFD_ASSERT (sgot != NULL);

  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (ht->dynamic_sections_created)
    {
      asection *splt = ht->splt;
      BFD_ASSERT (splt != NULL);
      BFD_ASSERT (sdyn != NULL); /* If dynamic sections created, .dynamic section must exist.  */

      if (sdyn->contents != NULL && sdyn->size > 0)
        {
          Elf32_External_Dyn *dyncon, *dynconend;

          dyncon = (Elf32_External_Dyn *) sdyn->contents;
          dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

          for (; dyncon < dynconend; dyncon++)
            {
              Elf_Internal_Dyn dyn;
              asection *srelplt_section;

              bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

              switch (dyn.d_tag)
                {
                default:
                  break;

                case DT_PLTGOT:
                  BFD_ASSERT (sgot->output_section != NULL);
                  dyn.d_un.d_ptr = sgot->output_section->vma + sgot->output_offset;
                  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
                  break;

                case DT_JMPREL:
                  srelplt_section = ht->srelplt;
                  dyn.d_un.d_ptr = (srelplt_section != NULL && srelplt_section->output_section != NULL)
                                     ? (srelplt_section->output_section->vma + srelplt_section->output_offset)
                                     : 0;
                  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
                  break;

                case DT_PLTRELSZ:
                  srelplt_section = ht->srelplt;
                  dyn.d_un.d_val = (srelplt_section != NULL) ? srelplt_section->size : 0;
                  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
                  break;
                }
            }
        }

      /* Fill in the first entry in the procedure linkage table.  */
      if (splt->size > 0 && splt->contents != NULL)
        {
          if (bfd_get_mach (output_bfd) == bfd_mach_cris_v32)
            {
              if (bfd_link_pic (info))
                {
                  memcpy (splt->contents, elf_cris_pic_plt0_entry_v32,
                          PLT_ENTRY_SIZE_V32);
                }
              else
                {
                  memcpy (splt->contents, elf_cris_plt0_entry_v32,
                          PLT_ENTRY_SIZE_V32);
                  BFD_ASSERT (sgot->output_section != NULL);
                  bfd_put_32 (output_bfd,
                              sgot->output_section->vma
                              + sgot->output_offset + 4,
                              splt->contents + 4);

                  BFD_ASSERT (splt->output_section != NULL);
                  elf_section_data (splt->output_section)->this_hdr.sh_entsize
                    = PLT_ENTRY_SIZE_V32;
                }
            }
          else
            {
              if (bfd_link_pic (info))
                {
                  memcpy (splt->contents, elf_cris_pic_plt0_entry,
                          PLT_ENTRY_SIZE);
                }
              else
                {
                  memcpy (splt->contents, elf_cris_plt0_entry,
                          PLT_ENTRY_SIZE);
                  BFD_ASSERT (sgot->output_section != NULL);
                  bfd_put_32 (output_bfd,
                              sgot->output_section->vma
                              + sgot->output_offset + 4,
                              splt->contents + 6);
                  bfd_put_32 (output_bfd,
                              sgot->output_section->vma
                              + sgot->output_offset + 8,
                              splt->contents + 14);

                  BFD_ASSERT (splt->output_section != NULL);
                  elf_section_data (splt->output_section)->this_hdr.sh_entsize
                    = PLT_ENTRY_SIZE;
                }
            }
        }
    }

  /* Fill in the first three entries in the global offset table.  */
  if (sgot->size > 0 && sgot->contents != NULL)
    {
      if (sdyn == NULL || sdyn->output_section == NULL)
        {
          bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents);
        }
      else
        {
          bfd_put_32 (output_bfd,
                      sdyn->output_section->vma + sdyn->output_offset,
                      sgot->contents);
        }
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + 4);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + 8);
    }

  BFD_ASSERT (sgot->output_section != NULL);
  elf_section_data (sgot->output_section)->this_hdr.sh_entsize = 4;

  return true;
}

/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *
cris_elf_gc_mark_hook (asection *sec,
		       struct bfd_link_info *info,
		       Elf_Internal_Rela *rel,
		       struct elf_link_hash_entry *h,
		       Elf_Internal_Sym *sym)
{
  /* Assuming 'rel' is always a valid pointer as per BFD hook contract.
     If 'rel' could be NULL, an explicit check would be needed here. */
  enum elf_cris_reloc_type r_type = ELF32_R_TYPE (rel->r_info);

  if (h != NULL && (r_type == R_CRIS_GNU_VTINHERIT || r_type == R_CRIS_GNU_VTENTRY))
    {
      return NULL;
    }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* The elf_backend_plt_sym_val hook function.  */

#define CRIS_PLT_GOT_OFFSET_IN_ENTRY 2

static bfd_vma
cris_elf_plt_sym_val (bfd_vma i ATTRIBUTE_UNUSED, const asection *plt,
		      const arelent *rel)
{
  bfd *abfd = plt->owner;

  asection *got = bfd_get_section_by_name (abfd, ".got");
  if (got == NULL)
    {
      return (bfd_vma) -1;
    }

  bfd_size_type plt_entry_size = (bfd_get_mach (abfd) == bfd_mach_cris_v32
                                  ? PLT_ENTRY_SIZE_V32 : PLT_ENTRY_SIZE);

  bfd_vma got_base_vma = (abfd->flags & EXEC_P) ? 0 : got->vma;

  bfd_size_type plt_sec_size = bfd_section_size (plt);

  for (bfd_size_type pltoffs = plt_entry_size;
       pltoffs < plt_sec_size;
       pltoffs += plt_entry_size)
    {
      bfd_byte gotoffs_raw[4];

      if (!bfd_get_section_contents (abfd, (asection *) plt,
                                     gotoffs_raw,
                                     pltoffs + CRIS_PLT_GOT_OFFSET_IN_ENTRY,
                                     sizeof (gotoffs_raw)))
        {
          return (bfd_vma) -1;
        }

      bfd_vma got_offset_val = bfd_get_32 (abfd, gotoffs_raw);

      if (got_offset_val + got_base_vma == rel->address)
        {
          return plt->vma + pltoffs;
        }
    }

  return (bfd_vma) -1;
}

/* Make sure we emit a GOT entry if the symbol was supposed to have a PLT
   entry but we found we will not create any.  Called when we find we will
   not have any PLT for this symbol, by for example
   elf_cris_adjust_dynamic_symbol when we're doing a proper dynamic link,
   or elf_cris_late_size_sections if no dynamic sections will be
   created (we're only linking static objects).  */

static bool
elf_cris_adjust_gotplt_to_got (struct elf_cris_link_hash_entry *h, void * p)
{
  struct bfd_link_info *info = (struct bfd_link_info *) p;

  /* Verify internal consistency of refcounts. */
  BFD_ASSERT (h->gotplt_refcount == 0
              || h->root.plt.refcount == -1
              || h->gotplt_refcount <= h->root.plt.refcount);

  /* If no GOTPLT entries are active for this symbol, there's nothing to do. */
  if (h->gotplt_refcount <= 0)
    return true;

  /* If a GOT entry already exists for this symbol, adjust its refcounts. */
  if (h->reg_got_refcount > 0)
    {
      h->root.got.refcount += h->gotplt_refcount;
      h->reg_got_refcount += h->gotplt_refcount;
    }
  else /* No GOT entry exists; a new one must be created. */
    {
      struct elf_cris_link_hash_table *cris_hash_table = elf_hash_table (info);
      asection *sgot = cris_hash_table->sgot;
      asection *srelgot = cris_hash_table->srelgot;

      /* Ensure .got and .rela.got sections exist, which is expected
         if GOTPLT relocations were present in the input. */
      BFD_ASSERT (sgot != NULL && srelgot != NULL);

      /* Update symbol's GOT refcounts. */
      BFD_ASSERT (h->root.got.refcount >= 0); /* Ensure non-negative before addition. */
      h->root.got.refcount += h->gotplt_refcount;
      h->reg_got_refcount = h->gotplt_refcount;

      /* Allocate space in the .got section for a new entry (4 bytes for a 32-bit address). */
      sgot->size += 4;

      /* Allocate corresponding relocation space in .rela.got. */
      srelgot->size += sizeof (Elf32_External_Rela);
    }

  /* The GOTPLT refcount has now been accounted for, so reset it. */
  h->gotplt_refcount = 0;

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

static bool
elf_cris_try_fold_plt_to_got (struct elf_cris_link_hash_entry *h, void * p)
{
  if (h == NULL || p == NULL)
    return false;

  struct bfd_link_info *info = (struct bfd_link_info *) p;

  if (h->root.got.refcount <= 0 || h->root.plt.refcount <= 0)
    return true;

  BFD_ASSERT (h->gotplt_refcount <= h->root.plt.refcount);

  if (h->gotplt_refcount == h->root.plt.refcount)
    {
      if (! elf_cris_adjust_gotplt_to_got (h, info))
	return false;

      h->root.plt.offset = (bfd_vma) -1;
    }

  return true;
}

/* Our own version of hide_symbol, so that we can adjust a GOTPLT reloc
   to use a GOT entry (and create one) rather than requiring a GOTPLT
   entry.  */

static void
elf_cris_hide_symbol (struct bfd_link_info *info,
		      struct elf_link_hash_entry *h,
		      bool force_local)
{
  struct elf_cris_link_hash_entry *cris_h = (struct elf_cris_link_hash_entry *) h;
  elf_cris_adjust_gotplt_to_got (cris_h, info);

  _bfd_elf_link_hash_hide_symbol (info, h, force_local);
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool
elf_cris_adjust_dynamic_symbol (struct bfd_link_info *info,
				struct elf_link_hash_entry *h)
{
  struct elf_cris_link_hash_table *htab = elf_cris_hash_table (info);
  if (htab == NULL)
    return false;

  bfd *dynobj = htab->root.dynobj;
  if (dynobj == NULL)
    return false;

  BFD_ASSERT (h->needs_plt
              || h->is_weakalias
              || (h->def_dynamic && h->ref_regular && !h->def_regular));

  bfd_size_type plt_entry_size = (bfd_get_mach (dynobj) == bfd_mach_cris_v32
                                  ? PLT_ENTRY_SIZE_V32 : PLT_ENTRY_SIZE);

  struct elf_cris_link_hash_entry *cris_h = (struct elf_cris_link_hash_entry *) h;

  if (h->type == STT_FUNC || h->needs_plt)
    {
      if (!bfd_link_pic (info) && !h->def_dynamic)
        {
          BFD_ASSERT (h->needs_plt);
          h->needs_plt = 0;
          h->plt.offset = (bfd_vma) -1;
          return elf_cris_adjust_gotplt_to_got (cris_h, info);
        }

      if (bfd_link_pic (info) && !elf_cris_try_fold_plt_to_got (cris_h, info))
        return false;

      if (h->plt.refcount <= 0)
        {
          h->needs_plt = 0;
          h->plt.offset = (bfd_vma) -1;
          return true;
        }

      if (h->dynindx == -1)
        {
          if (!bfd_elf_link_record_dynamic_symbol (info, h))
            return false;
        }

      asection *splt = htab->root.splt;
      if (splt == NULL)
        return false;

      if (splt->size == 0)
        splt->size += plt_entry_size;

      if (!bfd_link_pic (info) && !h->def_regular)
        {
          h->root.u.def.section = splt;
          h->root.u.def.value = splt->size;
        }

      if (bfd_link_pic (info) && h->got.refcount > 0)
        {
          h->got.refcount += h->plt.refcount;

          BFD_ASSERT ((splt->size % plt_entry_size) == 0);
          BFD_ASSERT (cris_h->gotplt_offset == 0);

          h->plt.offset = splt->size;
          splt->size += plt_entry_size;

          return true;
        }

      h->plt.offset = splt->size;
      splt->size += plt_entry_size;

      cris_h->gotplt_offset = htab->next_gotplt_entry;
      htab->next_gotplt_entry += 4;

      asection *sgotplt = htab->root.sgotplt;
      if (sgotplt == NULL)
        return false;
      sgotplt->size += 4;

      asection *srelplt = htab->root.srelplt;
      if (srelplt == NULL)
        return false;
      srelplt->size += sizeof (Elf32_External_Rela);

      return true;
    }

  h->plt.offset = (bfd_vma) -1;

  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      if (def == NULL || def->root.type != bfd_link_hash_defined)
        return false;
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return true;
    }

  if (bfd_link_pic (info))
    return true;

  if (!h->non_got_ref)
    return true;

  asection *dyn_data_section = NULL;
  asection *dyn_rela_section = NULL;

  if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      dyn_data_section = htab->root.sdynrelro;
      dyn_rela_section = htab->root.sreldynrelro;
    }
  else
    {
      dyn_data_section = htab->root.sdynbss;
      dyn_rela_section = htab->root.srelbss;
    }

  if (dyn_data_section == NULL || dyn_rela_section == NULL)
    return false;

  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      dyn_rela_section->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, dyn_data_section);
}

/* Adjust our "subclass" elements for an indirect symbol.  */

static void
elf_cris_copy_indirect_symbol (struct bfd_link_info *info,
			       struct elf_link_hash_entry *dir,
			       struct elf_link_hash_entry *ind)
{
  struct elf_cris_link_hash_entry *edir, *eind;

  edir = (struct elf_cris_link_hash_entry *) dir;
  eind = (struct elf_cris_link_hash_entry *) ind;

  if (eind->root.root.type != bfd_link_hash_indirect)
    {
      _bfd_elf_link_hash_copy_indirect (info, dir, ind);
      return;
    }

  BFD_ASSERT (edir->gotplt_offset == 0 || eind->gotplt_offset == 0);

  if (eind->pcrel_relocs_copied != NULL)
    {
      struct elf_cris_pcrel_relocs_copied *eind_current = eind->pcrel_relocs_copied;
      struct elf_cris_pcrel_relocs_copied *unmerged_eind_head = NULL;
      struct elf_cris_pcrel_relocs_copied **unmerged_eind_tail_ptr = &unmerged_eind_head;

      while (eind_current != NULL)
        {
          struct elf_cris_pcrel_relocs_copied *current_node_from_eind = eind_current;
          eind_current = eind_current->next; // Advance to the next node in eind's original list

          int found_match_in_edir = 0;
          for (struct elf_cris_pcrel_relocs_copied *edir_node = edir->pcrel_relocs_copied;
               edir_node != NULL; edir_node = edir_node->next)
            {
              if (edir_node->section == current_node_from_eind->section)
                {
                  edir_node->count += current_node_from_eind->count;
                  found_match_in_edir = 1;
                  // Node 'current_node_from_eind' is now conceptually consumed from eind's list
                  // (its data merged into edir_node). No explicit free as it's likely pool-allocated.
                  break;
                }
            }

          if (!found_match_in_edir)
            {
              // Node 'current_node_from_eind' did not merge; add it to the unmerged list.
              *unmerged_eind_tail_ptr = current_node_from_eind;
              unmerged_eind_tail_ptr = &current_node_from_eind->next;
              current_node_from_eind->next = NULL; // Terminate this node to form a proper list
            }
        }

      // The 'unmerged_eind_head' list now contains all nodes from 'eind' that were not merged.
      // Append the original 'edir->pcrel_relocs_copied' list to the end of this unmerged list.
      *unmerged_eind_tail_ptr = edir->pcrel_relocs_copied;

      // 'edir->pcrel_relocs_copied' now points to the combined list
      // (unmerged eind nodes followed by original edir nodes).
      edir->pcrel_relocs_copied = unmerged_eind_head;

      // Clear 'eind->pcrel_relocs_copied' as all its relevant data has been processed.
      eind->pcrel_relocs_copied = NULL;
    }

  // Replace XMOVE macros with explicit assignments for maintainability and readability.
  edir->gotplt_refcount += eind->gotplt_refcount;
  eind->gotplt_refcount = 0;

  edir->gotplt_offset += eind->gotplt_offset;
  eind->gotplt_offset = 0;

  edir->reg_got_refcount += eind->reg_got_refcount;
  eind->reg_got_refcount = 0;

  edir->tprel_refcount += eind->tprel_refcount;
  eind->tprel_refcount = 0;

  edir->dtp_refcount += eind->dtp_refcount;
  eind->dtp_refcount = 0;

  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

/* Look through the relocs for a section during the first phase.  */

static bool
setup_dynamic_structures_if_needed (bfd *abfd, struct bfd_link_info *info,
                                    asection *sec, Elf_Internal_Shdr *symtab_hdr,
                                    bfd **dynobj_ptr, asection **sgot_ptr,
                                    asection **srelgot_ptr, bfd_signed_vma **local_got_refcounts_ptr)
{
  if (*dynobj_ptr == NULL)
    {
      elf_hash_table (info)->dynobj = abfd;
      *dynobj_ptr = abfd;

      if (bfd_get_mach (*dynobj_ptr) == bfd_mach_cris_v10_v32)
        {
          _bfd_error_handler
            (_("%pB, section %pA: v10/v32 compatible object"
               " must not contain a PIC relocation"),
             abfd, sec);
          return false;
        }
    }

  if (*sgot_ptr == NULL)
    {
      if (!_bfd_elf_create_got_section (*dynobj_ptr, info))
        return false;
      *sgot_ptr = elf_hash_table (info)->sgot;
      *srelgot_ptr = elf_hash_table (info)->srelgot;
    }

  if (*local_got_refcounts_ptr == NULL)
    {
      bfd_size_type amt = LGOT_ALLOC_NELTS_FOR (symtab_hdr->sh_info) + 1;
      amt *= sizeof (bfd_signed_vma);
      bfd_signed_vma *new_refcounts = ((bfd_signed_vma *) bfd_zalloc (abfd, amt));
      if (new_refcounts == NULL)
        return false;

      *local_got_refcounts_ptr = new_refcounts + 1;
      elf_local_got_refcounts (abfd) = *local_got_refcounts_ptr;
    }
  return true;
}

static void
handle_plt_symbol_logic (struct elf_link_hash_entry *h)
{
  if (h == NULL)
    return;

  h->needs_plt = 1;
  if (h->plt.refcount != -1)
    h->plt.refcount++;
}

static bool
handle_regular_relocations (bfd *abfd, struct bfd_link_info *info,
                            asection *sec, bfd *dynobj,
                            asection **sreloc_ptr,
                            struct elf_link_hash_entry *h,
                            enum elf_cris_reloc_type r_type,
                            bool is_pcrel)
{
  if (h != NULL)
    {
      h->non_got_ref = 1;
      if (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT)
        handle_plt_symbol_logic(h);
    }

  if (!bfd_link_pic (info) || (sec->flags & SEC_ALLOC) == 0)
    return true;

  bool create_dyn_reloc_section = false;
  if (is_pcrel)
    {
      if (h != NULL && ELF_ST_VISIBILITY (h->other) != STV_DEFAULT)
        /* Local or hidden symbol, no dyn reloc.  */;
      else if (h != NULL && SYMBOLIC_BIND (info, h) && h->root.type != bfd_link_hash_defweak && h->def_regular)
        /* -Bsymbolic and defined, no dyn reloc.  */;
      else
        create_dyn_reloc_section = true;
    }
  else
    {
      if (h != NULL && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
        /* Weak undef or local, no dyn reloc.  */;
      else
        create_dyn_reloc_section = true;
    }

  if (create_dyn_reloc_section)
    {
      if (*sreloc_ptr == NULL)
        {
          *sreloc_ptr = _bfd_elf_make_dynamic_reloc_section (sec, dynobj, 2, abfd, /*rela?*/ true);
          if (*sreloc_ptr == NULL)
            return false;
        }
      if (!is_pcrel && (sec->flags & SEC_READONLY))
        info->flags |= DF_TEXTREL;
      (*sreloc_ptr)->size += sizeof (Elf32_External_Rela);

      if (is_pcrel && h != NULL)
        {
          struct elf_cris_link_hash_entry *eh = elf_cris_hash_entry (h);
          struct elf_cris_pcrel_relocs_copied *p;

          for (p = eh->pcrel_relocs_copied; p != NULL; p = p->next)
            if (p->section == sec)
              break;

          if (p == NULL)
            {
              p = ((struct elf_cris_pcrel_relocs_copied *)
                   bfd_alloc (dynobj, (bfd_size_type) sizeof *p));
              if (p == NULL)
                return false;
              p->next = eh->pcrel_relocs_copied;
              eh->pcrel_relocs_copied = p;
              p->section = sec;
              p->count = 0;
              p->r_type = r_type;
            }
          ++p->count;
        }
    }
  return true;
}

static bool
handle_got_logic (bfd *abfd, struct bfd_link_info *info,
                  asection *sgot, asection *srelgot,
                  struct elf_link_hash_entry *h,
                  unsigned long r_symndx, unsigned long current_r_symndx_lgot,
                  bfd_signed_vma *local_got_refcounts,
                  bfd_signed_vma current_got_element_size,
                  enum elf_cris_reloc_type r_type)
{
  if (h != NULL)
    {
      if (h->got.refcount == 0)
        {
          if (h->dynindx == -1)
            {
              if (!bfd_elf_link_record_dynamic_symbol (info, h))
                return false;
            }
        }
      h->got.refcount++;

      struct elf_cris_link_hash_entry *eh = elf_cris_hash_entry (h);
      switch (r_type)
        {
        case R_CRIS_16_GOT:
        case R_CRIS_32_GOT:
          if (eh->reg_got_refcount == 0)
            {
              sgot->size += current_got_element_size;
              srelgot->size += sizeof (Elf32_External_Rela);
            }
          eh->reg_got_refcount++;
          break;

        case R_CRIS_32_GD:
        case R_CRIS_16_GOT_GD:
        case R_CRIS_32_GOT_GD:
          if (eh->dtp_refcount == 0)
            {
              sgot->size += current_got_element_size;
              srelgot->size += sizeof (Elf32_External_Rela);
            }
          eh->dtp_refcount++;
          break;

        case R_CRIS_32_IE:
        case R_CRIS_32_GOT_TPREL:
        case R_CRIS_16_GOT_TPREL:
          if (eh->tprel_refcount == 0)
            {
              sgot->size += current_got_element_size;
              srelgot->size += sizeof (Elf32_External_Rela);
            }
          eh->tprel_refcount++;
          break;

        default:
          BFD_FAIL ();
          return false;
        }
    }
  else
    {
      if (local_got_refcounts[current_r_symndx_lgot] == 0)
        {
          sgot->size += current_got_element_size;
          if (bfd_link_pic (info))
            srelgot->size += sizeof (Elf32_External_Rela);
        }
      local_got_refcounts[current_r_symndx_lgot]++;
      local_got_refcounts[r_symndx]++;
    }
  return true;
}


static bool
cris_elf_check_relocs (bfd *abfd,
		       struct bfd_link_info *info,
		       asection *sec,
		       const Elf_Internal_Rela *relocs)
{
  struct elf_cris_link_hash_table * htab;
  bfd *dynobj;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_signed_vma *local_got_refcounts;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sgot;
  asection *srelgot;
  asection *sreloc = NULL; // sreloc is dynamically created if needed

  if (bfd_link_relocatable (info))
    return true;

  htab = elf_cris_hash_table (info);
  if (htab == NULL)
    return false;

  dynobj = elf_hash_table (info)->dynobj;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);
  local_got_refcounts = elf_local_got_refcounts (abfd);

  sgot = elf_hash_table (info)->sgot;
  srelgot = elf_hash_table (info)->srelgot;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry *h;
      unsigned long r_symndx;
      enum elf_cris_reloc_type r_type;
      bfd_signed_vma current_got_element_size = 4;
      unsigned long current_r_symndx_lgot;

      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_symndx < symtab_hdr->sh_info)
	{
	  h = NULL;
	  current_r_symndx_lgot = LGOT_REG_NDX (r_symndx);
	}
      else
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	  current_r_symndx_lgot = LGOT_REG_NDX (r_symndx);
	}

      // Stage 1: Dynamic Structure Setup
      bool needs_dyn_setup = false;
      switch (r_type)
        {
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
            needs_dyn_setup = true;
            break;
          default:
            break;
        }

      if (needs_dyn_setup)
        {
          if (!setup_dynamic_structures_if_needed(abfd, info, sec, symtab_hdr,
                                                   &dynobj, &sgot, &srelgot, &local_got_refcounts))
            return false;
        }

      // Stage 2: Warnings and Specific Parameter Adjustments
      switch (r_type)
        {
          case R_CRIS_32_IE:
          case R_CRIS_32_TPREL:
          case R_CRIS_16_TPREL:
          case R_CRIS_32_GD:
            if (bfd_link_pic (info))
              {
                _bfd_error_handler
                  (_("%pB, section %pA:\n  relocation %s not valid"
                     " in a shared object;"
                     " typically an option mixup, recompile with -fPIC"),
                   abfd, sec, cris_elf_howto_table[r_type].name);
              }
            break;
          default:
            break;
        }

      switch (r_type)
        {
          case R_CRIS_32_GD:
          case R_CRIS_16_GOT_GD:
          case R_CRIS_32_GOT_GD:
            current_got_element_size = 8;
            current_r_symndx_lgot = LGOT_DTP_NDX (r_symndx);
            break;

          case R_CRIS_32_IE:
          case R_CRIS_32_GOT_TPREL:
          case R_CRIS_16_GOT_TPREL:
            current_r_symndx_lgot = LGOT_TPREL_NDX (r_symndx);
            if (bfd_link_pic (info))
              info->flags |= DF_STATIC_TLS;
            break;
          default:
            break;
        }

      // Stage 3: Main Relocation Handling Logic
      switch (r_type)
        {
        case R_CRIS_16_GOTPLT:
        case R_CRIS_32_GOTPLT:
          if (h != NULL)
            {
              elf_cris_hash_entry (h)->gotplt_refcount++;
              handle_plt_symbol_logic(h);
              break;
            }
          /* Fall through for local symbols to generic GOT handling.  */

        case R_CRIS_32_IE:
        case R_CRIS_32_GD:
        case R_CRIS_16_GOT_GD:
        case R_CRIS_32_GOT_GD:
        case R_CRIS_32_GOT_TPREL:
        case R_CRIS_16_GOT_TPREL:
        case R_CRIS_16_GOT:
        case R_CRIS_32_GOT:
          if (!handle_got_logic (abfd, info, sgot, srelgot, h, r_symndx,
                                 current_r_symndx_lgot, local_got_refcounts,
                                 current_got_element_size, r_type))
            return false;
          break;

        case R_CRIS_16_DTPREL:
        case R_CRIS_32_DTPREL:
        case R_CRIS_32_GOTREL:
          if (local_got_refcounts == NULL)
            return false;
          local_got_refcounts[-1]++;
          break;

        case R_CRIS_32_PLT_GOTREL:
          if (local_got_refcounts == NULL)
            return false;
          local_got_refcounts[-1]++;
          handle_plt_symbol_logic(h);
          break;

        case R_CRIS_32_PLT_PCREL:
          handle_plt_symbol_logic(h);
          break;

        case R_CRIS_8:
        case R_CRIS_16:
        case R_CRIS_32:
          if (!handle_regular_relocations (abfd, info, sec, dynobj,
                                            &sreloc, h, r_type, false))
            return false;
          break;

        case R_CRIS_8_PCREL:
        case R_CRIS_16_PCREL:
        case R_CRIS_32_PCREL:
          if (!handle_regular_relocations (abfd, info, sec, dynobj,
                                            &sreloc, h, r_type, true))
            return false;
          break;

        case R_CRIS_GNU_VTINHERIT:
          if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
            return false;
          break;

        case R_CRIS_GNU_VTENTRY:
          if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
            return false;
          break;

        case R_CRIS_16_TPREL:
        case R_CRIS_32_TPREL:
          // Warning already handled in Stage 2. No further action here.
          break;

        default:
          bfd_set_error (bfd_error_bad_value);
          return false;
        }
    }

  return true;
}

/* Set the sizes of the dynamic sections.  */

static bool
elf_cris_process_section_content_and_alloc(bfd *dynobj, asection *s,
                                           struct elf_cris_link_hash_table *htab,
                                           struct bfd_link_info *info,
                                           bool *relocs_found)
{
  const char *name = bfd_section_name(s);

  if (strcmp(name, ".plt") == 0)
    {
      /* No specific size adjustment needed for .plt in this block */
    }
  else if (strcmp(name, ".got.plt") == 0)
    {
      /* The .got.plt contains the .got header as well as the
         actual .got.plt contents. The .got header may contain a
         R_CRIS_DTPMOD entry at index 3. */
      if (htab->dtpmod_refcount != 0)
        s->size += 8;
    }
  else if (startswith(name, ".rela"))
    {
      if (strcmp(name, ".rela.got") == 0 && htab->dtpmod_refcount != 0 && bfd_link_pic(info))
        s->size += sizeof(Elf32_External_Rela);

      if (s->size != 0)
        {
          /* Remember whether there are any reloc sections other than .rela.plt. */
          if (strcmp(name, ".rela.plt") != 0)
            *relocs_found = true;

          /* We use the reloc_count field as a counter if we need
             to copy relocs into the output file. */
          s->reloc_count = 0;
        }
    }
  else if (!startswith(name, ".got") && strcmp(name, ".dynbss") != 0 && s != htab->root.sdynrelro)
    {
      /* It's not one of our sections, so don't allocate space. */
      return true; /* Continue to next section */
    }

  if (s->size == 0)
    {
      /* If we don't need this section, strip it from the
         output file. */
      s->flags |= SEC_EXCLUDE;
      return true; /* Continue to next section */
    }

  if ((s->flags & SEC_HAS_CONTENTS) == 0)
    {
      return true; /* Continue to next section */
    }

  /* Allocate memory for the section contents. We use bfd_zalloc here
     in case unused entries are not reclaimed before the section's
     contents are written out. */
  s->contents = (bfd_byte *)bfd_zalloc(dynobj, s->size);
  if (s->contents == NULL)
    return false;

  s->alloced = 1;
  return true;
}

static bool
elf_cris_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
			     struct bfd_link_info *info)
{
  struct elf_cris_link_hash_table *htab = elf_cris_hash_table (info);
  if (htab == NULL)
    return false;

  bfd *dynobj = htab->root.dynobj;
  if (dynobj == NULL)
    return true;

  if (htab->root.dynamic_sections_created)
    {
      /* Set the contents of the .interp section to the interpreter. */
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  asection *s_interp = bfd_get_linker_section (dynobj, ".interp");
	  BFD_ASSERT (s_interp != NULL);
	  s_interp->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  s_interp->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	  s_interp->alloced = 1;
	}
    }
  else
    {
      /* Adjust all expected GOTPLT uses to use a GOT entry instead. */
      elf_cris_link_hash_traverse (htab, elf_cris_adjust_gotplt_to_got, info);

      /* We may have created entries in the .rela.got section.
	 However, if we are not creating the dynamic sections, we will
	 not actually use these entries. Reset the size of .rela.got,
	 which will cause it to get stripped from the output file
	 below. */
      asection *s_relgot = htab->root.srelgot;
      if (s_relgot != NULL)
	s_relgot->size = 0;
    }

  /* If this is a -Bsymbolic shared link, then we need to discard all PC
     relative relocs against symbols defined in a regular object.  We
     allocated space for them in the check_relocs routine, but we will not
     fill them in in the relocate_section routine. We also discard space
     for relocs that have become for local symbols due to symbol
     visibility changes. For programs, we discard space for relocs for
     symbols not referenced by any dynamic object. */
  if (bfd_link_pic (info))
    elf_cris_link_hash_traverse (htab,
				 elf_cris_discard_excess_dso_dynamics,
				 info);
  else
    elf_cris_link_hash_traverse (htab,
				 elf_cris_discard_excess_program_dynamics,
				 info);

  /* The check_relocs and adjust_dynamic_symbol entry points have
     determined the sizes of the various dynamic sections. Allocate
     memory for them. */
  bool relocs_present = false;
  for (asection *s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (!elf_cris_process_section_content_and_alloc(dynobj, s, htab, info, &relocs_present))
        return false;
    }

  return _bfd_elf_add_dynamic_tags (output_bfd, info, relocs_present);
}

/* This function is called via elf_cris_link_hash_traverse if we are
   creating a shared object.  In the -Bsymbolic case, it discards the
   space allocated to copy PC relative relocs against symbols which
   are defined in regular objects.  For the normal non-symbolic case,
   we also discard space for relocs that have become local due to
   symbol visibility changes.  We allocated space for them in the
   check_relocs routine, but we won't fill them in in the
   relocate_section routine.  */

static void
discard_pcrel_relocs(struct elf_cris_link_hash_entry *h, struct bfd_link_info *info)
{
  struct elf_cris_pcrel_relocs_copied *s;
  for (s = h->pcrel_relocs_copied; s != NULL; s = s->next)
    {
      asection *sreloc = _bfd_elf_get_dynamic_reloc_section (elf_hash_table (info)->dynobj,
                                                              s->section,
                                                              true);
      sreloc->size -= s->count * sizeof (Elf32_External_Rela);
    }
}

static void
warn_readonly_pcrel_relocs(struct elf_cris_link_hash_entry *h, struct bfd_link_info *info)
{
  struct elf_cris_pcrel_relocs_copied *s;
  for (s = h->pcrel_relocs_copied; s != NULL; s = s->next)
    {
      if ((s->section->flags & SEC_READONLY) != 0)
        {
          _bfd_error_handler
            (_("%pB, section `%pA', to symbol `%s':"
               " relocation %s should not be used"
               " in a shared object; recompile with -fPIC"),
             s->section->owner,
             s->section,
             h->root.root.root.string,
             cris_elf_howto_table[s->r_type].name);

          info->flags |= DF_TEXTREL;
        }
    }
}

static bool
elf_cris_discard_excess_dso_dynamics (struct elf_cris_link_hash_entry *h,
				      void * inf)
{
  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  bool has_regular_definition = h->root.def_regular;
  bool is_forced_local = h->root.forced_local;
  bool is_symbolic_bind = SYMBOLIC_BIND (info, &h->root);

  if (has_regular_definition && (is_forced_local || is_symbolic_bind))
    {
      discard_pcrel_relocs(h, info);
      return true;
    }

  warn_readonly_pcrel_relocs(h, info);
  return true;
}

/* This function is called via elf_cris_link_hash_traverse if we are *not*
   creating a shared object.  We discard space for relocs for symbols put
   in the .got, but which we found we do not have to resolve at run-time.  */

static bool
elf_cris_discard_excess_program_dynamics (struct elf_cris_link_hash_entry *h,
					  void * link_info_ptr)
{
  struct bfd_link_info *link_info = (struct bfd_link_info *) link_info_ptr;
  struct elf_link_hash_table *eh = elf_hash_table (link_info);

  bool is_locally_defined_or_has_plt_ref = !h->root.def_dynamic || h->root.plt.refcount > 0;
  bool has_got_ref = h->reg_got_refcount > 0;
  bool dynamic_sections_created = eh->dynamic_sections_created;

  if (is_locally_defined_or_has_plt_ref && has_got_ref && dynamic_sections_created)
    {
      bfd *dynobj = eh->dynobj;
      asection *srelgot = eh->srelgot;

      BFD_ASSERT (dynobj != NULL);
      BFD_ASSERT (srelgot != NULL);

      srelgot->size -= sizeof (Elf32_External_Rela);
    }

  bool is_locally_defined = !h->root.def_dynamic;
  bool is_not_dynamic_symbol = !h->root.dynamic;
  bool is_not_referenced_by_dso = !h->root.ref_dynamic;
  bool has_dynamic_index = h->root.dynindx != -1;
  bool not_exporting_all_dynamic = !link_info->export_dynamic;
  bool is_function_or_not_exporting_data = (h->root.type == STT_FUNC || !link_info->dynamic_data);

  if (is_locally_defined
      && is_not_dynamic_symbol
      && is_not_referenced_by_dso
      && has_dynamic_index
      && not_exporting_all_dynamic
      && is_function_or_not_exporting_data)
    {
      h->root.dynindx = -1;
      _bfd_elf_strtab_delref (eh->dynstr,
                              h->root.dynstr_index);
    }

  return true;
}

/* Reject a file depending on presence and expectation of prefixed
   underscores on symbols.  */

static bool
cris_elf_object_p (bfd *abfd)
{
  const unsigned int e_flags = elf_elfheader (abfd)->e_flags;

  if (! cris_elf_set_mach_from_flags (abfd, e_flags))
    return false;

  const char expected_leading_char = (e_flags & EF_CRIS_UNDERSCORE) ? '_' : 0;

  return (bfd_get_symbol_leading_char (abfd) == expected_leading_char);
}

/* Mark presence or absence of leading underscore.  Set machine type
   flags from mach type.  */

static bool
cris_elf_final_write_processing (bfd *abfd)
{
  unsigned long e_flags = elf_elfheader (abfd)->e_flags;

  e_flags &= ~EF_CRIS_UNDERSCORE;
  if (bfd_get_symbol_leading_char (abfd) == '_')
    e_flags |= EF_CRIS_UNDERSCORE;

  switch (bfd_get_mach (abfd))
    {
    case bfd_mach_cris_v0_v10:
      e_flags |= EF_CRIS_VARIANT_ANY_V0_V10;
      break;

    case bfd_mach_cris_v10_v32:
      e_flags |= EF_CRIS_VARIANT_COMMON_V10_V32;
      break;

    case bfd_mach_cris_v32:
      e_flags |= EF_CRIS_VARIANT_V32;
      break;

    default:
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  elf_elfheader (abfd)->e_flags = e_flags;
  return _bfd_elf_final_write_processing (abfd);
}

/* Set the mach type from e_flags value.  */

static bool
cris_elf_set_mach_from_flags (bfd *abfd,
			      unsigned long flags)
{
  enum bfd_mach_type machine_type;
  bool success = true;

  switch (flags & EF_CRIS_VARIANT_MASK)
    {
    case EF_CRIS_VARIANT_ANY_V0_V10:
      machine_type = bfd_mach_cris_v0_v10;
      break;

    case EF_CRIS_VARIANT_V32:
      machine_type = bfd_mach_cris_v32;
      break;

    case EF_CRIS_VARIANT_COMMON_V10_V32:
      machine_type = bfd_mach_cris_v10_v32;
      break;

    default:
      bfd_set_error (bfd_error_wrong_format);
      success = false;
      break;
    }

  if (success)
    {
      bfd_default_set_arch_mach (abfd, bfd_arch_cris, machine_type);
    }

  return success;
}

/* Display the flags field.  */

static bool
cris_elf_print_private_bfd_data (bfd *abfd, void * ptr)
{
  if (abfd == NULL || ptr == NULL)
    return false;

  FILE *file = (FILE *) ptr;

  _bfd_elf_print_private_bfd_data (abfd, ptr);

  unsigned long cris_flags = elf_elfheader (abfd)->e_flags;

  if (fprintf (file, _("private flags = %lx:"), cris_flags) < 0)
    return false;

  if (cris_flags & EF_CRIS_UNDERSCORE)
  {
    if (fprintf (file, _(" [symbols have a _ prefix]")) < 0)
      return false;
  }

  unsigned long cris_variant = cris_flags & EF_CRIS_VARIANT_MASK;
  if (cris_variant == EF_CRIS_VARIANT_COMMON_V10_V32)
  {
    if (fprintf (file, _(" [v10 and v32]")) < 0)
      return false;
  }
  else if (cris_variant == EF_CRIS_VARIANT_V32)
  {
    if (fprintf (file, _(" [v32]")) < 0)
      return false;
  }

  if (fputc ('\n', file) == EOF)
    return false;

  return true;
}

/* Don't mix files with and without a leading underscore.  */

static bool
cris_elf_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  int imach, omach;

  if (! _bfd_generic_verify_endian_match (ibfd, info))
    return false;

  if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour
      || bfd_get_flavour (obfd) != bfd_target_elf_flavour)
    return true;

  imach = bfd_get_mach (ibfd);

  if (! elf_flags_init (obfd))
    {
      /* This happens when ld starts out with a 'blank' output file.  */
      elf_flags_init (obfd) = true;

      /* We ignore the linker-set mach, and instead set it according to
	 the first input file.  This would also happen if we could
	 somehow filter out the OUTPUT_ARCH () setting from elf.sc.
	 This allows us to keep the same linker config across
	 cris(v0..v10) and crisv32.  The drawback is that we can't force
	 the output type, which might be a sane thing to do for a
	 v10+v32 compatibility object.  */
      if (! bfd_set_arch_mach (obfd, bfd_arch_cris, imach))
	return false;
    }

  if (bfd_get_symbol_leading_char (ibfd)
      != bfd_get_symbol_leading_char (obfd))
    {
      const char *symbol_error_msg =
        (bfd_get_symbol_leading_char (ibfd) == '_')
	? _("%pB: uses _-prefixed symbols, but writing file with non-prefixed symbols")
	: _("%pB: uses non-prefixed symbols, but writing file with _-prefixed symbols");
      _bfd_error_handler (symbol_error_msg, ibfd);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  omach = bfd_get_mach (obfd);

  if (imach != omach)
    {
      /* We can get an incompatible combination only if either is
	 bfd_mach_cris_v32, and the other one isn't compatible.  */
      if ((imach == bfd_mach_cris_v32
	   && omach != bfd_mach_cris_v10_v32)
	  || (omach == bfd_mach_cris_v32
	      && imach != bfd_mach_cris_v10_v32))
	{
	  const char *mach_error_msg =
	    ((imach == bfd_mach_cris_v32)
	     ? _("%pB contains CRIS v32 code, incompatible"
		 " with previous objects")
	     : _("%pB contains non-CRIS-v32 code, incompatible"
		 " with previous objects"));
	  _bfd_error_handler (mach_error_msg, ibfd);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}

      /* We don't have to check the case where the input is compatible
	 with v10 and v32, because the output is already known to be set
	 to the other (compatible) mach.  */
      if (omach == bfd_mach_cris_v10_v32
	  && ! bfd_set_arch_mach (obfd, bfd_arch_cris, imach))
	return false;
    }

  return true;
}

/* Do side-effects of e_flags copying to obfd.  */

static bool
cris_elf_copy_private_bfd_data (const bfd *ibfd, bfd *obfd)
{
  if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour
      || bfd_get_flavour (obfd) != bfd_target_elf_flavour)
    return true;

  if (!_bfd_elf_copy_private_bfd_data (ibfd, obfd))
    return false;

  return bfd_set_arch_mach (obfd, bfd_arch_cris, bfd_get_mach (ibfd));
}

static enum elf_reloc_type_class
elf_cris_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			   const asection *rel_sec ATTRIBUTE_UNUSED,
			   const Elf_Internal_Rela *rela)
{
  switch (ELF32_R_TYPE (rela->r_info))
    {
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

static bfd_vma
elf_cris_got_elt_size (bfd *abfd ATTRIBUTE_UNUSED,
		       struct bfd_link_info *info ATTRIBUTE_UNUSED,
		       struct elf_link_hash_entry *hr,
		       bfd *ibfd,
		       unsigned long symndx)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) hr;
  bfd_vma eltsiz = 0;

  unsigned long reg_refcount = 0;
  unsigned long dtp_refcount = 0;
  unsigned long tprel_refcount = 0;

  if (h == NULL)
    {
      bfd_signed_vma *local_got_refcounts = elf_local_got_refcounts (ibfd);
      BFD_ASSERT (local_got_refcounts != NULL);

      reg_refcount = local_got_refcounts[LGOT_REG_NDX (symndx)];
      dtp_refcount = local_got_refcounts[LGOT_DTP_NDX (symndx)];
      tprel_refcount = local_got_refcounts[LGOT_TPREL_NDX (symndx)];
    }
  else
    {
      struct elf_cris_link_hash_entry *hh = elf_cris_hash_entry (h);
      reg_refcount = hh->reg_got_refcount;
      dtp_refcount = hh->dtp_refcount;
      tprel_refcount = hh->tprel_refcount;
    }

  if (reg_refcount > 0)
    {
      /* We can't have a variable referred to both as a regular
         variable and through TLS relocs.  */
      BFD_ASSERT (dtp_refcount == 0 && tprel_refcount == 0);
      return 4;
    }

  if (dtp_refcount > 0)
    eltsiz += 8;

  if (tprel_refcount > 0)
    eltsiz += 4;

  /* We're only called when h->got.refcount is non-zero, so we must
     have a non-zero size.  */
  BFD_ASSERT (eltsiz != 0);
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
