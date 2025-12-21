from dataclasses import dataclass
from typing import Self

from .chunk_base import ChunkBase
from .generic_chunk import GenericChunk


@dataclass
class YkyiInfoEntry:
    """YKYI Info Entry (key-value pair)"""

    key: str
    value: str


@dataclass
class YkyiChunk(ChunkBase):
    """YKYI Information Chunk

    This chunk contains metadata about the song in a text-based format.
    The structure consists of:
    - 32 bytes of header data
    - Text data with semicolon-separated key:value pairs

    Known fields (keys are in half-width katakana):
    - Artist name (romanized and katakana reading)
    - Song title (romanized and katakana reading)
    - Composer/Lyricist information
    - Release date
    - PSVV: Version
    - PSVS: Serial number
    """

    # Header fields (32 bytes total)
    unknown_00: bytes  # 0x00-0x0F: 16 bytes, usually zero
    flags_10: int  # 0x10-0x11: 2 bytes, e.g., 0x1818
    unknown_12: int  # 0x12-0x13: 2 bytes
    value_14: int  # 0x14-0x15: 2 bytes, e.g., 0x0278
    unknown_16: bytes  # 0x16-0x1F: 10 bytes, usually zero

    # Text data entries
    entries: list[YkyiInfoEntry]

    # Raw text data for preservation
    raw_text: bytes

    @classmethod
    def from_generic(cls, generic: GenericChunk) -> Self:
        """From Generic Chunk

        Args:
            generic (GenericChunk): Generic Chunk

        Returns:
            Self: Instance of this class
        """
        payload = generic.payload

        # Parse header (32 bytes)
        unknown_00 = payload[0x00:0x10]
        flags_10 = int.from_bytes(payload[0x10:0x12], "big")
        unknown_12 = int.from_bytes(payload[0x12:0x14], "big")
        value_14 = int.from_bytes(payload[0x14:0x16], "big")
        unknown_16 = payload[0x16:0x20]

        # Parse text data (after 32-byte header)
        raw_text = payload[0x20:]
        entries = cls._parse_text_data(raw_text)

        return cls(
            generic.id,
            unknown_00,
            flags_10,
            unknown_12,
            value_14,
            unknown_16,
            entries,
            raw_text,
        )

    @staticmethod
    def _parse_text_data(raw_text: bytes) -> list[YkyiInfoEntry]:
        """Parse text data into key-value entries

        Args:
            raw_text (bytes): Raw text data

        Returns:
            list[YkyiInfoEntry]: List of parsed entries
        """
        entries: list[YkyiInfoEntry] = []

        # Remove trailing null bytes
        text_stripped = raw_text.rstrip(b"\x00")

        # Split by semicolon
        parts = text_stripped.split(b";")

        for part in parts:
            if not part:
                continue

            # Try to decode with EUC-JP (Japanese encoding used in YKYI chunks)
            try:
                decoded = part.decode("euc_jp")
            except UnicodeDecodeError:
                # Fallback to latin-1 for raw bytes
                decoded = part.decode("latin-1")

            # Split by colon to get key and value
            if ":" in decoded:
                # Find the first colon as separator
                colon_idx = decoded.index(":")
                key = decoded[:colon_idx]
                value = decoded[colon_idx + 1 :]
                entries.append(YkyiInfoEntry(key, value))
            else:
                # No colon, treat entire string as value with empty key
                entries.append(YkyiInfoEntry("", decoded))

        return entries

    def _payload_buffer(self) -> bytes:
        """Payload Buffer

        Returns:
            bytes: Payload Buffer
        """
        buffer = bytearray()

        # Header
        buffer.extend(self.unknown_00)
        buffer.extend(self.flags_10.to_bytes(2, "big"))
        buffer.extend(self.unknown_12.to_bytes(2, "big"))
        buffer.extend(self.value_14.to_bytes(2, "big"))
        buffer.extend(self.unknown_16)

        # Text data (use raw_text to preserve original encoding)
        buffer.extend(self.raw_text)

        return bytes(buffer)

    def get_entry(self, key: str) -> str | None:
        """Get entry value by key

        Args:
            key (str): Key to search for

        Returns:
            str | None: Value if found, None otherwise
        """
        for entry in self.entries:
            if entry.key == key:
                return entry.value
        return None

    def get_psvv(self) -> str | None:
        """Get PSV Version

        Returns:
            str | None: PSV Version if found
        """
        return self.get_entry("PSVV")

    def get_psvs(self) -> str | None:
        """Get PSV Serial

        Returns:
            str | None: PSV Serial if found
        """
        return self.get_entry("PSVS")

    def to_json_serializable(self) -> dict:
        """Convert to JSON serializable dict

        Returns:
            dict: JSON serializable representation
        """
        return {
            "id": self.id.hex(" ").upper(),
            "header": {
                "unknown_00": self.unknown_00.hex(" ").upper(),
                "flags_10": f"0x{self.flags_10:04X}",
                "unknown_12": f"0x{self.unknown_12:04X}",
                "value_14": f"0x{self.value_14:04X}",
                "unknown_16": self.unknown_16.hex(" ").upper(),
            },
            "entries": [{"key": e.key, "value": e.value} for e in self.entries],
        }
