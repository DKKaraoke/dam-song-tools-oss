from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import BytesIO
from logging import getLogger
from typing import Self, Union, BinaryIO

from sprc.header import SprcHeader
from .chunks import OkdChunk, ChunkBase, read_chunk
from .okd_file_scramble import (
    choose_scramble_pattern_index,
    scramble,
    detect_scramble_pattern_index,
    descramble,
)


@dataclass
class OkdHeaderBase(ABC):
    """OKD Header Base Class"""

    MAGIC_BYTES = b"YKS1"
    FIXED_PART_LENGTH = 40

    length: int
    version: str
    id_karaoke: int
    adpcm_offset: int
    encryption_mode: int

    @staticmethod
    def _read_common(
        stream: BinaryIO,
        scramble_pattern_index: int | None = None,
    ) -> tuple[int, str, int, int, int, bytes]:
        """Read Common Part

        Args:
            stream (BinaryIO): Input stream
            scramble_pattern_index (int): Scramble pattern index

        Raises:
            ValueError: Invalid `magic_bytes`

        Returns:
            tuple[int, str, int, int, int, bytes]: length, version, id_karaoke, adpcm_offset, encryption_mode and optional_data
        """
        if scramble_pattern_index is None:
            fixed_part_buffer = stream.read(OkdHeaderBase.FIXED_PART_LENGTH)
        else:
            fixed_part_stream = BytesIO()
            scramble_pattern_index = descramble(
                stream,
                fixed_part_stream,
                scramble_pattern_index,
                OkdHeaderBase.FIXED_PART_LENGTH,
            )
            fixed_part_stream.seek(0)
            fixed_part_buffer = fixed_part_stream.read()
        if len(fixed_part_buffer) < OkdHeaderBase.FIXED_PART_LENGTH:
            raise ValueError("Too less read bytes.")

        magic_bytes = fixed_part_buffer[0:4]
        if magic_bytes != OkdHeaderBase.MAGIC_BYTES:
            raise ValueError("Invalid `magic_bytes`.")
        length = int.from_bytes(fixed_part_buffer[4:8], "big")
        version = fixed_part_buffer[8:24].decode("ascii")
        id_karaoke = int.from_bytes(fixed_part_buffer[24:28], "big")
        adpcm_offset = int.from_bytes(fixed_part_buffer[28:32], "big")
        encryption_mode = int.from_bytes(fixed_part_buffer[32:36], "big")
        optional_data_length = int.from_bytes(fixed_part_buffer[36:40], "big")

        if scramble_pattern_index is None:
            variable_part_buffer = stream.read(optional_data_length)
        else:
            variable_part_stream = BytesIO()
            descramble(
                stream,
                variable_part_stream,
                scramble_pattern_index,
                optional_data_length,
            )
            variable_part_stream.seek(0)
            variable_part_buffer = variable_part_stream.read()
        if len(variable_part_buffer) < optional_data_length:
            raise ValueError("Too less read bytes.")

        optional_data = variable_part_buffer

        return (
            length,
            version,
            id_karaoke,
            adpcm_offset,
            encryption_mode,
            optional_data,
        )

    @staticmethod
    @abstractmethod
    def optional_data_buffer_size() -> int:
        """Size of Optional Data Buffer

        Returns:
            bytes: Size of Optional Data Buffer
        """
        pass

    @abstractmethod
    def _optional_data_buffer(self) -> bytes:
        """Optional Data Buffer

        Returns:
            bytes: Optional Data Buffer
        """
        pass

    def write(self, stream: BinaryIO) -> None:
        """Write

        Args:
            stream (BinaryIO): Output stream
        """
        stream.write(OkdHeaderBase.MAGIC_BYTES)
        stream.write(self.length.to_bytes(4, "big"))
        stream.write(self.version.encode("ascii").ljust(16, b"\x00"))
        stream.write(self.id_karaoke.to_bytes(4, "big"))
        stream.write(self.adpcm_offset.to_bytes(4, "big"))
        stream.write(self.encryption_mode.to_bytes(4, "big"))
        optional_data_buffer = self._optional_data_buffer()
        stream.write(len(optional_data_buffer).to_bytes(4, "big"))
        stream.write(optional_data_buffer)


@dataclass
class OkdGenericHeader(OkdHeaderBase):
    """OKD Generic Header"""

    optional_data: bytes

    @classmethod
    def read(
        cls,
        stream: BinaryIO,
        scramble_pattern_index: int | None = None,
    ) -> Self:
        """Read

        Args:
            stream (BinaryIO): Input stream
            scramble_pattern_index (int): Scramble pattern index

        Returns:
            Self: Instance of this class
        """
        length, version, id_karaoke, adpcm_offset, encryption_mode, optional_data = (
            OkdHeaderBase._read_common(stream, scramble_pattern_index)
        )
        return cls(
            length,
            version,
            id_karaoke,
            adpcm_offset,
            encryption_mode,
            optional_data,
        )

    @staticmethod
    def optional_data_buffer_size() -> int:
        raise NotImplementedError()

    def _optional_data_buffer(self) -> bytes:
        return self.optional_data


@dataclass
class YksOkdHeader(OkdHeaderBase):
    """YKS OKD Header"""

    @classmethod
    def from_generic(cls, generic: OkdGenericHeader) -> Self:
        """From Generic OKD Header

        Args:
            generic (OkdGenericHeader): Generic OKD Header

        Returns:
            Self: Instance of this class
        """
        return cls(
            generic.length,
            generic.version,
            generic.id_karaoke,
            generic.adpcm_offset,
            generic.encryption_mode,
        )

    @staticmethod
    def optional_data_buffer_size() -> int:
        return 0

    def _optional_data_buffer(self) -> bytes:
        return b""


@dataclass
class MmtOkdHeader(OkdHeaderBase):
    """MMT OKD Header"""

    yks_chunks_length: int
    mmt_chunks_length: int
    yks_chunks_crc: int
    crc: int

    @classmethod
    def from_generic(cls, generic: OkdGenericHeader) -> Self:
        """From Generic OKD Header

        Args:
            generic (OkdGenericHeader): Generic OKD Header

        Returns:
            Self: Instance of this class
        """
        yks_chunks_length = int.from_bytes(generic.optional_data[0:4], "big")
        mmt_chunks_length = int.from_bytes(generic.optional_data[4:8], "big")
        yks_chunks_crc = int.from_bytes(generic.optional_data[8:10], "big")
        crc = int.from_bytes(generic.optional_data[10:12], "big")
        return cls(
            generic.length,
            generic.version,
            generic.id_karaoke,
            generic.adpcm_offset,
            generic.encryption_mode,
            yks_chunks_length,
            mmt_chunks_length,
            yks_chunks_crc,
            crc,
        )

    @staticmethod
    def optional_data_buffer_size() -> int:
        return 12

    def _optional_data_buffer(self) -> bytes:
        buffer = self.yks_chunks_length.to_bytes(4, "big")
        buffer += self.mmt_chunks_length.to_bytes(4, "big")
        buffer += self.yks_chunks_crc.to_bytes(2, "big")
        buffer += self.crc.to_bytes(2, "big")
        return buffer


@dataclass
class MmkOkdHeader(OkdHeaderBase):
    """MMK OKD Header"""

    yks_chunks_length: int
    mmt_chunks_length: int
    mmk_chunks_length: int
    yks_chunks_crc: int
    yks_mmt_chunks_crc: int
    crc: int

    @classmethod
    def from_generic(cls, generic: OkdGenericHeader) -> Self:
        """From Generic OKD Header

        Args:
            generic (OkdGenericHeader): Generic OKD Header

        Returns:
            Self: Instance of this class
        """
        yks_chunks_length = int.from_bytes(generic.optional_data[0:4], "big")
        mmt_chunks_length = int.from_bytes(generic.optional_data[4:8], "big")
        mmk_chunks_length = int.from_bytes(generic.optional_data[8:12], "big")
        yks_chunks_crc = int.from_bytes(generic.optional_data[12:14], "big")
        yks_mmt_chunks_crc = int.from_bytes(generic.optional_data[14:16], "big")
        crc = int.from_bytes(generic.optional_data[16:18], "big")
        return cls(
            generic.length,
            generic.version,
            generic.id_karaoke,
            generic.adpcm_offset,
            generic.encryption_mode,
            yks_chunks_length,
            mmt_chunks_length,
            mmk_chunks_length,
            yks_chunks_crc,
            yks_mmt_chunks_crc,
            crc,
        )

    @staticmethod
    def optional_data_buffer_size() -> int:
        return 20

    def _optional_data_buffer(self) -> bytes:
        buffer = self.yks_chunks_length.to_bytes(4, "big")
        buffer += self.mmt_chunks_length.to_bytes(4, "big")
        buffer += self.mmk_chunks_length.to_bytes(4, "big")
        buffer += self.yks_chunks_crc.to_bytes(2, "big")
        buffer += self.yks_mmt_chunks_crc.to_bytes(2, "big")
        buffer += self.crc.to_bytes(2, "big")
        # Padding
        buffer += b"\x00" * 2
        return buffer


@dataclass
class SprOkdHeader(OkdHeaderBase):
    """SPR OKD Header"""

    yks_chunks_length: int
    mmt_chunks_length: int
    mmk_chunks_length: int
    spr_chunks_length: int
    yks_chunks_crc: int
    yks_mmt_chunks_crc: int
    yks_mmt_mmk_chunks_crc: int
    crc: int

    @classmethod
    def from_generic(cls, generic: OkdGenericHeader) -> Self:
        """From Generic OKD Header

        Args:
            generic (OkdGenericHeader): Generic OKD Header

        Returns:
            Self: Instance of this class
        """
        yks_chunks_length = int.from_bytes(generic.optional_data[0:4], "big")
        mmt_chunks_length = int.from_bytes(generic.optional_data[4:8], "big")
        mmk_chunks_length = int.from_bytes(generic.optional_data[8:12], "big")
        spr_chunks_length = int.from_bytes(generic.optional_data[12:16], "big")
        yks_chunks_crc = int.from_bytes(generic.optional_data[16:18], "big")
        yks_mmt_chunks_crc = int.from_bytes(generic.optional_data[18:20], "big")
        yks_mmt_mmk_chunks_crc = int.from_bytes(generic.optional_data[20:22], "big")
        crc = int.from_bytes(generic.optional_data[22:24], "big")

        return cls(
            generic.length,
            generic.version,
            generic.id_karaoke,
            generic.adpcm_offset,
            generic.encryption_mode,
            yks_chunks_length,
            mmt_chunks_length,
            mmk_chunks_length,
            spr_chunks_length,
            yks_chunks_crc,
            yks_mmt_chunks_crc,
            yks_mmt_mmk_chunks_crc,
            crc,
        )

    @staticmethod
    def optional_data_buffer_size() -> int:
        return 24

    def _optional_data_buffer(self) -> bytes:
        buffer = self.yks_chunks_length.to_bytes(4, "big")
        buffer += self.mmt_chunks_length.to_bytes(4, "big")
        buffer += self.mmk_chunks_length.to_bytes(4, "big")
        buffer += self.spr_chunks_length.to_bytes(4, "big")
        buffer += self.yks_chunks_crc.to_bytes(2, "big")
        buffer += self.yks_mmt_chunks_crc.to_bytes(2, "big")
        buffer += self.yks_mmt_mmk_chunks_crc.to_bytes(2, "big")
        buffer += self.crc.to_bytes(2, "big")
        return buffer


@dataclass
class DioOkdHeader(OkdHeaderBase):
    """DIO OKD Header"""

    yks_chunks_length: int
    mmt_chunks_length: int
    mmk_chunks_length: int
    spr_chunks_length: int
    dio_chunks_length: int
    yks_chunks_crc: int
    yks_mmt_chunks_crc: int
    yks_mmt_mmk_chunks_crc: int
    yks_mmt_mmk_spr_chunks_crc: int
    crc: int

    @classmethod
    def from_generic(cls, generic: OkdGenericHeader) -> Self:
        """From Generic OKD Header

        Args:
            generic (OkdGenericHeader): Generic OKD Header

        Returns:
            Self: Instance of this class
        """
        yks_chunks_length = int.from_bytes(generic.optional_data[0:4], "big")
        mmt_chunks_length = int.from_bytes(generic.optional_data[4:8], "big")
        mmk_chunks_length = int.from_bytes(generic.optional_data[8:12], "big")
        spr_chunks_length = int.from_bytes(generic.optional_data[12:16], "big")
        dio_chunks_length = int.from_bytes(generic.optional_data[16:20], "big")
        yks_chunks_crc = int.from_bytes(generic.optional_data[20:22], "big")
        yks_mmt_chunks_crc = int.from_bytes(generic.optional_data[22:24], "big")
        yks_mmt_mmk_chunks_crc = int.from_bytes(generic.optional_data[24:26], "big")
        yks_mmt_mmk_spr_chunks_crc = int.from_bytes(generic.optional_data[26:28], "big")
        crc = int.from_bytes(generic.optional_data[28:30], "big")
        return cls(
            generic.length,
            generic.version,
            generic.id_karaoke,
            generic.adpcm_offset,
            generic.encryption_mode,
            yks_chunks_length,
            mmt_chunks_length,
            mmk_chunks_length,
            spr_chunks_length,
            dio_chunks_length,
            yks_chunks_crc,
            yks_mmt_chunks_crc,
            yks_mmt_mmk_chunks_crc,
            yks_mmt_mmk_spr_chunks_crc,
            crc,
        )

    @staticmethod
    def optional_data_buffer_size() -> int:
        return 32

    def _optional_data_buffer(self) -> bytes:
        buffer = self.yks_chunks_length.to_bytes(4, "big")
        buffer += self.mmt_chunks_length.to_bytes(4, "big")
        buffer += self.mmk_chunks_length.to_bytes(4, "big")
        buffer += self.spr_chunks_length.to_bytes(4, "big")
        buffer += self.dio_chunks_length.to_bytes(4, "big")
        buffer += self.yks_chunks_crc.to_bytes(2, "big")
        buffer += self.yks_mmt_chunks_crc.to_bytes(2, "big")
        buffer += self.yks_mmt_mmk_chunks_crc.to_bytes(2, "big")
        buffer += self.yks_mmt_mmk_spr_chunks_crc.to_bytes(2, "big")
        buffer += self.crc.to_bytes(2, "big")
        # Padding
        buffer += b"\x00" * 2
        return buffer


OkdHeader = Union[OkdGenericHeader, YksOkdHeader, MmtOkdHeader, MmkOkdHeader, SprOkdHeader, DioOkdHeader]


def read_okd_header(
    stream: BinaryIO, scramble_pattern_index: int | None = None
) -> OkdHeader:
    """Read OKD Header

    Args:
        stream (BinaryIO): Input stream
        scramble_pattern_index (int | None, optional): Scramble pattern index. Defaults to None.

    Returns:
        OkdHeader: OKD Header
    """
    generic = OkdGenericHeader.read(stream, scramble_pattern_index)

    if len(generic.optional_data) == YksOkdHeader.optional_data_buffer_size():
        return YksOkdHeader.from_generic(generic)
    elif len(generic.optional_data) == MmtOkdHeader.optional_data_buffer_size():
        return MmtOkdHeader.from_generic(generic)
    elif len(generic.optional_data) == MmkOkdHeader.optional_data_buffer_size():
        return MmkOkdHeader.from_generic(generic)
    elif len(generic.optional_data) == SprOkdHeader.optional_data_buffer_size():
        return SprOkdHeader.from_generic(generic)
    elif len(generic.optional_data) == DioOkdHeader.optional_data_buffer_size():
        return DioOkdHeader.from_generic(generic)

    return generic


@dataclass
class OkdFile:
    """OKD File"""

    __logger = getLogger(__name__)

    header: OkdHeader
    chunks: list[OkdChunk]

    @classmethod
    def read(cls, stream: BinaryIO) -> Self:
        """Read

        Args:
            stream (BinaryIO): Input stream

        Raises:
            ValueError: Invalid `magic_bytes`

        Returns:
            Self: Instance of this class
        """
        if SprcHeader.has_sprc_header(stream):
            # Validate SPRC Header
            OkdFile.__logger.info("SPRC Header detected.")
            sprc_header = SprcHeader.read(stream)
            if not sprc_header.validate_crc(stream):
                raise ValueError("SPRC Header CRC validation failed.")
            OkdFile.__logger.info("SPRC Header CRC validation succeeded.")

        scramble_pattern_index = detect_scramble_pattern_index(
            stream, OkdHeaderBase.MAGIC_BYTES
        )

        # Header
        header = read_okd_header(stream, scramble_pattern_index)
        if header.adpcm_offset == 0:
            scrambled_length = (header.length + 8) - (
                OkdHeaderBase.FIXED_PART_LENGTH + header.optional_data_buffer_size()
            )
            plaintext_length = 0
        else:
            scrambled_length = header.adpcm_offset - (
                OkdHeaderBase.FIXED_PART_LENGTH + header.optional_data_buffer_size()
            )
            plaintext_length = (header.length + 8) - header.adpcm_offset
        chunks_stream = BytesIO()
        if scramble_pattern_index is None:
            chunks_stream.write(stream.read())
        else:
            descramble(stream, chunks_stream, scramble_pattern_index, scrambled_length)
            # Plaintext part
            chunks_stream.write(stream.read(plaintext_length))

        chunks: list[OkdChunk] = []
        chunks_stream.seek(0)
        while True:
            if ChunkBase.peek_header(chunks_stream) is None:
                # Reached to End of File
                break
            chunk = read_chunk(chunks_stream)
            chunks.append(chunk)

        return cls(header, chunks)

    def write(self, stream: BinaryIO, should_scramble: bool = False) -> None:
        """Write

        Args:
            stream (BinaryIO): Output stream
            scramble (bool, optional): Scramble. Defaults to False.
        """
        # Make chunks buffer
        chunks_stream = BytesIO()
        for chunk in self.chunks:
            chunk.write(chunks_stream)
        self.header.length = (
            OkdHeaderBase.FIXED_PART_LENGTH
            + len(self.header._optional_data_buffer())
            + chunks_stream.tell()
            - 8
        )
        self.header.encryption_mode = 1 if should_scramble else 0
        chunks_stream.seek(0)

        # Make header buffer
        header_stream = BytesIO()
        self.header.write(header_stream)
        header_stream.seek(0)

        if should_scramble:
            scramble_pattern_index = choose_scramble_pattern_index()
            scramble(header_stream, stream, scramble_pattern_index)
            scramble(chunks_stream, stream, scramble_pattern_index)
        else:
            stream.write(header_stream.read())
            stream.write(chunks_stream.read())
        # End of file
        stream.write(b"\x00\x00\x00\x00")
