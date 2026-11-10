"""Build a bootable, offline Alpine image from the three upstream archives."""

import argparse
import gzip
import io
import stat
import tarfile
from pathlib import Path

import pycdlib


def file_from_archive(archive, suffix):
    with tarfile.open(archive, ignore_zeros=True) as source:
        for member in source:
            if member.name.endswith(suffix) and member.isfile():
                return source.extractfile(member).read()
    raise ValueError(f'{suffix} missing from {archive}')


def pad(data):
    return data + b'\0' * ((-len(data)) % 4)


def cpio_entry(name, content, mode, inode):
    filename = name.encode() + b'\0'
    fields = (inode, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(filename), 0)
    header = b'070701' + ''.join(f'{value:08x}' for value in fields).encode()
    return pad(header + filename) + pad(content)


def initramfs(rootfs, custom):
    index = 0
    with tarfile.open(rootfs) as source:
        for member in source:
            name = member.name.removeprefix('./').lstrip('/')
            if name in ('', '.'):
                continue
            if member.isdir():
                mode, data = stat.S_IFDIR, b''
            elif member.issym():
                mode, data = stat.S_IFLNK, member.linkname.encode()
            elif member.isfile() or member.islnk():
                mode, data = stat.S_IFREG, source.extractfile(member).read()
            else:
                continue
            index += 1
            yield cpio_entry(name, data, mode | member.mode, index)
    for name, data in custom.items():
        index += 1
        yield cpio_entry(name, data, stat.S_IFREG | 0o755, index)
    yield cpio_entry('TRAILER!!!', b'', 0, index + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('upstream', type=Path)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    kernel_package = args.upstream / 'linux-virt.apk'
    syslinux_package = args.upstream / 'syslinux.apk'
    module = gzip.decompress(file_from_archive(kernel_package, '/e1000.ko.gz'))
    if b'depends=\x00' not in module:
        raise ValueError('The e1000 module has dependencies that must be included')
    image = gzip.compress(b''.join(initramfs(args.upstream / 'alpine-root.tar.gz', {
        'soc-init': Path(__file__).with_name('init.sh').read_text(encoding='utf-8').encode(),
        'soc-lab': args.binary.read_bytes(),
        'soc-e1000.ko': module,
    })), compresslevel=6, mtime=0)
    config = (b'DEFAULT soc\nPROMPT 0\nTIMEOUT 1\n'
              b'LABEL soc\n KERNEL vmlinuz\n INITRD initrd.gz\n'
              b' APPEND console=tty0 console=ttyS0,115200 loglevel=4 rdinit=/soc-init\n')
    iso = pycdlib.PyCdlib()
    iso.new(vol_ident='SOC_TIER1_DEMO')
    files = {
        '/ISOLINUX.BIN;1': file_from_archive(syslinux_package, '/isolinux.bin'),
        '/LDLINUX.C32;1': file_from_archive(syslinux_package, '/ldlinux.c32'),
        '/ISOLINUX.CFG;1': config,
        '/VMLINUZ.;1': file_from_archive(kernel_package, 'boot/vmlinuz-virt'),
        '/INITRD.GZ;1': image,
    }
    for name, data in files.items():
        iso.add_fp(io.BytesIO(data), len(data), iso_path=name)
    iso.add_eltorito('/ISOLINUX.BIN;1', bootcatfile='/BOOT.CAT;1', boot_load_size=4, boot_info_table=True)
    iso.write(args.output)
    iso.close()


if __name__ == '__main__':
    main()
