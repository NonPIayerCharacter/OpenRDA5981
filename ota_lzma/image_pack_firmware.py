import os
import sys
import struct
import zlib
import time


"""
#define IMAGE_MAGIC         0xAEAE
struct image_header
{
    uint16_t magic;
    uint8_t  encrypt_algo;
    uint8_t  resv[1];

    uint8_t  version[VERSION_SZ];

    uint32_t crc32;
    uint32_t size;
	//uint8_t  padding[4060];
};
#define FIRMWARE_MAGIC      0xEAEA
struct firmware_info
{
    uint32_t magic;
    uint8_t  version[VERSION_SZ];

    uint32_t addr;
    uint32_t size;
    uint32_t crc32;
    uint32_t bootaddr;    //new
};
"""


def pack_image(filename, version, bootaddr):
    fname = os.path.splitext(filename)

    print("firmware:", filename)

    with open(filename, "rb") as f:
        data = f.read()

    firmware_magic = 0xEAEA
    firmware_addr = 0x18004000

    crc32 = zlib.crc32(data) & 0xFFFFFFFF
    crc32 ^= 0xFFFFFFFF
    size = len(data)

    print("    size:", size)
    print("   version:", version)
    print("   crc32: %08x" % crc32)

    if 0x18001000 <= bootaddr < 0x18400000:
        print("bootaddr:%08x" % bootaddr)
    else:
        print("bootaddr(%08x) is invalid, or no input, disable it" % bootaddr)
        bootaddr = 0

    # Ensure version is bytes of correct length (24 bytes padded)
    version_bytes = version.encode("ascii", errors="ignore")[:24].ljust(24, b'\0')

    # Pack header (format adjusted for Python 3)
    header = struct.pack(
        "<L24sLLLLL4048s",  # Little-endian
        firmware_magic,
        version_bytes,
        firmware_addr,
        size,
        crc32,
        bootaddr,
        firmware_magic,
        b'\0' * 4048
    )

    output_file = fname[0] + "_fwpacked.bin"
    with open(output_file, "wb") as f:
        f.write(header)
        f.write(data)

    print("Packed image written to:", output_file)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(sys.argv[0], "filename version [bootaddr]")
        sys.exit(0)

    if len(sys.argv) == 4:
        pack_image(sys.argv[1], sys.argv[2], int(sys.argv[3], 16))
    else:
        pack_image(sys.argv[1], sys.argv[2], 0)
