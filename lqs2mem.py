#!/usr/bin/env python
#
# lqs2mem.py - Convert libvirt save files or qemu savevm dumps into raw
#              physical memory images
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development, L.P.
#
# Authors: Juerg Haefliger <juerg.haefliger@hpe.com>
#
# Based on lqs2mem originally written by Andrew Tappert <andrew@pikewerks.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.

from __future__ import print_function

import argparse
import struct
import sys

# -----------------------------------------------------------------------------
# Libvirt defines and structs (v1.3.4)
#
# libvirt's QEMU save file format is:
#   - Header (virQEMUSaveHeader)
#   - Domain XML config data
#   - QEMU savevm data

# From src/qemu/qemu_driver.c

QEMU_SAVE_MAGIC   = "LibvirtQemudSave"
QEMU_SAVE_PARTIAL = "LibvirtQemudPart"
QEMU_SAVE_VERSION = 2

# struct _virQEMUSaveHeader {
#     char magic[sizeof(QEMU_SAVE_MAGIC)-1];
#     uint32_t version;
#     uint32_t xml_len;
#     uint32_t was_running;
#     uint32_t compressed;
#     uint32_t unused[15];
# };

# -----------------------------------------------------------------------------
# QEMU defines and structs (v2.6.0)
#
# The conversion of a QEMU savevm file into a raw physical memory image is
# based on function qemu_loadvm_state in migartion/savevm.c. Each section has
# a different handler function and save/load functions are scattered throughout
# the QEMU code base. Comments in our section handler functions reference the
# corresponding QEMU savevm/vmstate load functions.

# From include/migration/migration.h

QEMU_VM_FILE_MAGIC          = 0x5145564d
QEMU_VM_FILE_VERSION_COMPAT = 0x00000002
QEMU_VM_FILE_VERSION        = 0x00000003
QEMU_VM_EOF                 = 0x00
QEMU_VM_SECTION_START       = 0x01
QEMU_VM_SECTION_PART        = 0x02
QEMU_VM_SECTION_END         = 0x03
QEMU_VM_SECTION_FULL        = 0x04
QEMU_VM_SUBSECTION          = 0x05
QEMU_VM_VMDESCRIPTION       = 0x06
QEMU_VM_CONFIGURATION       = 0x07
QEMU_VM_COMMAND             = 0x08
QEMU_VM_SECTION_FOOTER      = 0x7e

SEC_TYPE_NAME = (
    'EOF',
    'SECTION_START',
    'SECTION_PART',
    'SECTION_END',
    'SECTION_FULL',
    'SUBSECTION',
    'VMDESCRIPTION',
    'CONIGURATION',
    'COMMAND',
)

# From migration/ram.c

RAM_SAVE_FLAG_FULL     = 0x01  # Obsolete, not used anymore
RAM_SAVE_FLAG_COMPRESS = 0x02
RAM_SAVE_FLAG_MEM_SIZE = 0x04
RAM_SAVE_FLAG_PAGE     = 0x08
RAM_SAVE_FLAG_EOS      = 0x10
RAM_SAVE_FLAG_CONTINUE = 0x20
RAM_SAVE_FLAG_XBZRLE   = 0x40
# 0x80 is reserved in migration.h start with 0x100 next
RAM_SAVE_FLAG_COMPRESS_PAGE = 0x100


# From migration/qemu-file.c

def qemu_get_byte(fhi):
    '''
    Read one byte from file
    '''
    return struct.unpack('B', fhi.read(1))[0]


def qemu_get_be32(fhi):
    '''
    Read an unsigned int (32 bit, big endian) from file
    '''
    return struct.unpack('>I', fhi.read(4))[0]


def qemu_get_be64(fhi):
    '''
    Read an unsigned long (64 bit, big endian) from file
    '''
    return struct.unpack('>Q', fhi.read(8))[0]


# -----------------------------------------------------------------------------
# Globals

# Assuming 4k page sizes
PAGE_SIZE = 4096
PAGE_MASK = 0xfffffffffffff000

# Defines for seek()
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

# Verbosity level
VERBOSE = 0

# Number of pages written to disk and ram block name
PAGE_COUNT = 0
RAM_NAME = None


# -----------------------------------------------------------------------------
# Function declarations

def dprint(level, *args):
    '''
    Debug print
    '''
    if level <= VERBOSE:
        print(str(args[0]) % args[1:])


def check_libvirt(fhi, fho):
    '''
    Check for libvirt's QEMU save header
    '''
    # Read the header magic
    magic = fhi.read(len(QEMU_SAVE_MAGIC))
    if magic != QEMU_SAVE_MAGIC:
        print('Invalid Libvirt-QEMU-save magic')
        fhi.seek(0, SEEK_SET)
        if fho is None:
            return 0
        else:
            return 1

    # Read the rest of the header struct (19 4-byte unsigned integers)
    header = struct.unpack('<' + 'I' * 19, fhi.read(4 * 19))
    version, xml_len, dummy_was_running, dummy_compressed = header[0:4]

    if version != QEMU_VM_FILE_VERSION_COMPAT:
        print('Invalid Libvirt-QEMU-save version (%x)' % version)
        return 1

    print('Valid Libvirt-QEMU-save magic and version')

    # Read (skip over) libvirt's config XML
    xml = fhi.read(xml_len)

    # Write the XML to file
    if fho is not None:
        fho.write(xml)

    return 0


def check_qemu(fhi):
    '''
    Check for QEMU's save VM header
    '''
    val = qemu_get_be32(fhi)
    if val != QEMU_VM_FILE_MAGIC:
        print('Invalid QEMU-savevm magic')
        return 1

    val = qemu_get_be32(fhi)
    if val != QEMU_VM_FILE_VERSION:
        print('Unsupported QEMU-savevm version')
        return 1

    print('Valid QEMU-savevm magic and version')
    return 0


def write_page(fho, addr, data):
    '''
    Write a memory page to file
    '''
    global PAGE_COUNT

    # Account for the 512 MB 'hole' from 3.5 GB to 4 GB for the memory mapped
    # PCI devices
    if addr >= 0xe0000000:
        addr += 0x20000000

    fho.seek(addr, SEEK_SET)

    if isinstance(data, int):
        fho.write(struct.pack('B', data) * PAGE_SIZE)
    else:
        fho.write(data)

    PAGE_COUNT += 1


def ram_block_from_stream(fhi, flags):
    '''
    Get the 'ram' block name from file
    Based on 'ram_block_from_stream' from QEMU migration/ram.c
    '''
    global RAM_NAME

    if flags & RAM_SAVE_FLAG_CONTINUE:
        if RAM_NAME is None:
            print('Bad migration stream')
            return None
    else:
        ram_name_len = qemu_get_byte(fhi)
        RAM_NAME = fhi.read(ram_name_len)

        dprint(2, '    ram name: %s' % RAM_NAME)

    return RAM_NAME


def process_section_ram(fhi, fho, sec_version, dump_name):
    '''
    Process a 'ram' section

    Loosly based on 'ram_load' from QEMU migration/ram.c
    '''
    if sec_version != 4:
        print('Unsupported \'ram\' section version: %d' % sec_version)
        return 1

    while True:
        offset = fhi.tell()
        addr = qemu_get_be64(fhi)
        flags = addr & ~PAGE_MASK
        addr &= PAGE_MASK

        dprint(3, '    offset:    %x' % offset)
        dprint(3, '    addr:      %x' % addr)
        dprint(3, '    flags:     %x' % flags)

        if flags & (RAM_SAVE_FLAG_COMPRESS | RAM_SAVE_FLAG_PAGE |
                    RAM_SAVE_FLAG_COMPRESS_PAGE | RAM_SAVE_FLAG_XBZRLE):
            ram_name = ram_block_from_stream(fhi, flags)
            if ram_name is None:
                return 1

        ram_flags = flags & ~RAM_SAVE_FLAG_CONTINUE

        if ram_flags == RAM_SAVE_FLAG_MEM_SIZE:
            total_ram = addr
            dprint(2, '    total ram: %d (%d MB)' % (addr, addr / (1 << 20)))

            dump_ram_exists = False
            while total_ram:
                block_name_len = qemu_get_byte(fhi)
                block_name = fhi.read(block_name_len)
                block_len = qemu_get_be64(fhi)

                kb = block_len >> 10 if (block_len >> 10) > 0 else 0
                mb = block_len >> 20 if (block_len >> 20) > 0 else 0

                print('section = %-32s size = %5d [%s] %12d [bytes]' %
                      (block_name,
                       mb if mb > 0 else kb if kb > 0 else block_len,
                       "MB" if mb > 0 else "KB" if kb > 0 else "bytes",
                       block_len))

                if dump_name is not None and block_name == dump_name:
                    dump_ram_exists = True

                total_ram -= block_len

            if dump_name is not None and not dump_ram_exists:
                print('Section not found: %s' % dump_name)
                return 1

        elif ram_flags == RAM_SAVE_FLAG_COMPRESS:
            fill_byte = qemu_get_byte(fhi)

            dprint(3, '    fill byte: %02x' % fill_byte)

            if ram_name == dump_name:
                write_page(fho, addr, fill_byte)

        elif ram_flags == RAM_SAVE_FLAG_PAGE:
            page = fhi.read(PAGE_SIZE)

            dprint(3, '    page data: ' +
                   ' '.join('%02x' % ord(x) for x in page[0:16]) + ' ...')

            if ram_name == dump_name:
                write_page(fho, addr, page)

        elif ram_flags == RAM_SAVE_FLAG_EOS:
            return 0

        else:
            print('Invalid or unsupported \'ram\' flags: %x' % flags)
            return 1


# def process_section_block(fhi, fho, sec_version, dump_name):
#     '''
#     Process a 'block' section
#     '''
#     return 0


SECTION_OPS = {
    'ram': process_section_ram,
    # 'block': process_section_block,
}


def process_infile(fhi, fho, dump_name):
    '''
    Process the input file
    '''
    # Verify the file format
    if check_libvirt(fhi, None) or check_qemu(fhi):
        print('Unrecognized file format')
        return 1

    sec_count = 0
    sec_header = {}
    while True:
        sec_count += 1
        offset = fhi.tell()
        sec_type = qemu_get_byte(fhi)

        dprint(1, 'section %d:' % sec_count)
        dprint(1, '  file offset:  %d' % offset)
        dprint(1, '  section type: %d (%s)' % (sec_type,
                                               SEC_TYPE_NAME[sec_type]))

        if sec_type == QEMU_VM_EOF:
            return 0

        elif sec_type == QEMU_VM_CONFIGURATION:
            size = qemu_get_be32(fhi)
            text = fhi.read(size)

            dprint(1, '  text:         %s' % text)
            return 0

        elif (sec_type == QEMU_VM_SECTION_START or
              sec_type == QEMU_VM_SECTION_FULL):
            # Read the section header
            sec_id = qemu_get_be32(fhi)
            sec_name_len = qemu_get_byte(fhi)
            sec_name = fhi.read(sec_name_len)
            sec_inst_id = qemu_get_be32(fhi)
            sec_version = qemu_get_be32(fhi)

            dprint(1, '  section id:   %d (%s)' % (sec_id, sec_name))
            dprint(1, '  instance id:  %d' % sec_inst_id)
            dprint(1, '  version:      %d' % sec_version)

            # Store the section header in a hash for later lookups
            sec_header[sec_id] = {'id': sec_id,
                                  'name': sec_name,
                                  'version': sec_version}

            # Process the section
            if SECTION_OPS[sec_name](fhi, fho, sec_version, dump_name):
                return 1

            # Short-cycle the pocessing of the input file if we're only listing
            # RAM sections
            if ((sec_type == QEMU_VM_SECTION_START and sec_name == 'ram' and
                 dump_name is None)):
                return 0

        elif (sec_type == QEMU_VM_SECTION_PART or
              sec_type == QEMU_VM_SECTION_END):
            # Read the section id and lookup the header
            sec_id = qemu_get_be32(fhi)
            sec_name = sec_header[sec_id]['name']
            sec_version = sec_header[sec_id]['version']

            dprint(1, '  section id:   %d (%s)' % (sec_id, sec_name))

            # Process the section
            if SECTION_OPS[sec_name](fhi, fho, sec_version, dump_name):
                return 1

            # We're only interested (and fully support) RAM sections, so short-
            # cycle the processing of the input file if we're done with them
            if sec_type == QEMU_VM_SECTION_END and sec_name == 'ram':
                return 0

        else:
            print('Unsupported section type: %d' % sec_type)
            return 1


# -----------------------------------------------------------------------------
# Main entry point

def main():
    '''
    Main entry point
    '''
    global VERBOSE

    aparser = argparse.ArgumentParser()
    aparser.add_argument('infile', metavar='INFILE', help='input file to '
                         'process')
    aparser.add_argument('-x', '--xml', action='store_true', help='write the '
                         'libvirt XML config to OUTFILE')
    aparser.add_argument('-s', '--section', metavar='SECTION', help='write '
                         'section SECTION to OUTFILE')
    aparser.add_argument('outfile', nargs='?', metavar='OUTFILE',
                         help='output file to write data to')
    aparser.add_argument('-v', '--verbose', action='count', help='increase '
                         'verbosity (can be specified multiple times)')

    aargs = aparser.parse_args()
    if aargs.verbose is not None:
        VERBOSE = aargs.verbose

    # Validate the arguments
    if aargs.xml and aargs.section is not None:
        aparser.error('conflicting arguments')
    if (aargs.xml or aargs.section is not None) and aargs.outfile is None:
        aparser.error('too few arguments')
    if not aargs.xml and aargs.section is None and aargs.outfile is not None:
        aparser.error('unrecognized arguments: %s' % aargs.outfile)

    # Dump the XML and exit
    if aargs.xml:
        with open(aargs.infile, 'rb') as fhi:
            with open(aargs.outfile, 'wb') as fho:
                retval = check_libvirt(fhi, fho)
                if not retval:
                    print('XML config written to %s' % aargs.outfile)
                return retval

    # Dump the selected section and exit
    if aargs.section is not None:
        with open(aargs.infile, 'rb') as fhi:
            with open(aargs.outfile, 'wb') as fho:
                retval = process_infile(fhi, fho, aargs.section)
                if not retval:
                    print('Section \'%s\' (%d pages, %d bytes) written to %s' %
                          (aargs.section, PAGE_COUNT, PAGE_COUNT * PAGE_SIZE,
                           aargs.outfile))
                return retval

    # List sections and exit
    with open(aargs.infile, 'rb') as fhi:
        process_infile(fhi, None, None)
    return 0

if __name__ == '__main__':
    sys.exit(main())
