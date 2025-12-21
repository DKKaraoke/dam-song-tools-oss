from typing import BinaryIO

from .generic_chunk import GenericChunk
from .ykyi_chunk import YkyiChunk
from .p_track_info_chunk import (
    PTrackInfoChannelInfoEntry,
    PTrackInfoEntry,
    PTrackInfoChunk,
)
from .p3_track_info_chunk import P3TrackInfoChunk
from .extended_p_track_info_chunk import (
    ExtendedPTrackInfoChannelInfoEntry,
    ExtendedPTrackInfoEntry,
    ExtendedPTrackInfoChunk,
)
from .m_track_chunk import MTrackChunk
from .p_track_chunk import PTrackChunk
from .adpcm_chunk import AdpcmChunk
from .okd_chunk import OkdChunk


def read_chunk(stream: BinaryIO) -> OkdChunk:
    """Read Chunk

    Args:
        stream (BufferedReader): Input stream

    Returns:
        OkdChunk: OKD Chunk
    """
    generic = GenericChunk.read(stream)

    if generic.id == b"YKYI":
        return YkyiChunk.from_generic(generic)
    elif generic.id == b"YPTI":
        return PTrackInfoChunk.from_generic(generic)
    elif generic.id == b"YP3I":
        return P3TrackInfoChunk.from_generic(generic)
    elif generic.id == b"YPXI":
        return ExtendedPTrackInfoChunk.from_generic(generic)
    elif generic.id[0:3] == b"\xffMR":
        return MTrackChunk.from_generic(generic)
    elif generic.id[0:3] == b"\xffPR":
        return PTrackChunk.from_generic(generic)
    elif generic.id == b"YADD":
        return AdpcmChunk.from_generic(generic)

    return generic


def p_track_info_chunk_by_p_track_chunks(
    p_track_chunks: list[PTrackChunk],
) -> PTrackInfoChunk | ExtendedPTrackInfoChunk:
    if len(p_track_chunks) <= 2:
        p_track_info_entries_1: list[PTrackInfoEntry] = []
        for p_track_chunk in p_track_chunks:
            ports = (
                0x0001
                << PTrackChunk.CHUNK_NUMBER_PORT_MAP[p_track_chunk.track_number()]
            )
            sysex_ports = 4 if p_track_chunk.track_number() >= 2 else 1

            track_info_channel_info_entries_1: list[PTrackInfoChannelInfoEntry] = []
            for channel in range(16):
                exists_message = p_track_chunk.exists_channel_message(channel)
                channel_attribute = (
                    127 if p_track_chunk.track_number() == 1 and channel == 9 else 255
                )
                track_info_channel_info_entries_1.append(
                    PTrackInfoChannelInfoEntry(
                        channel_attribute if exists_message else 0,
                        ports,
                        0x00,
                        0x00,
                    )
                )

            p_track_info_entries_1.append(
                PTrackInfoEntry(
                    p_track_chunk.track_number(),
                    0x40,
                    0x0000,
                    [0] * 16,
                    [0] * 16,
                    track_info_channel_info_entries_1,
                    sysex_ports,
                )
            )

        return PTrackInfoChunk(b"YPTI", p_track_info_entries_1)

    else:
        p_track_info_entries_2: list[ExtendedPTrackInfoEntry] = []
        for p_track_chunk in p_track_chunks:
            ports = (
                0x0001
                << PTrackChunk.CHUNK_NUMBER_PORT_MAP[p_track_chunk.track_number()]
            )
            sysex_ports = 4 if p_track_chunk.track_number() >= 2 else 1

            track_info_channel_info_entries_2: list[
                ExtendedPTrackInfoChannelInfoEntry
            ] = []
            for channel in range(16):
                exists_message = p_track_chunk.exists_channel_message(channel)
                channel_attribute = (
                    127 if p_track_chunk.track_number() == 1 and channel == 9 else 255
                )
                track_info_channel_info_entries_2.append(
                    ExtendedPTrackInfoChannelInfoEntry(
                        channel_attribute if exists_message else 0,
                        ports,
                        0x00,
                        0x00,
                        0x00,
                    )
                )

            p_track_info_entries_2.append(
                ExtendedPTrackInfoEntry(
                    p_track_chunk.track_number(),
                    0x40,
                    0x00,
                    [0] * 16,
                    [0] * 16,
                    track_info_channel_info_entries_2,
                    sysex_ports,
                    0x00,
                )
            )

        return ExtendedPTrackInfoChunk(
            b"YPXI", b"\x00\x00\x00\x00\x00\x00\x00\x00", 0, p_track_info_entries_2
        )


def p3_track_info_chunk_by_p_track_chunks(
    p_track_chunk: PTrackChunk,
) -> P3TrackInfoChunk:
    track_info_channel_info_entries: list[PTrackInfoChannelInfoEntry] = []
    for channel in range(16):
        exists_message = p_track_chunk.exists_channel_message(channel)
        track_info_channel_info_entries.append(
            PTrackInfoChannelInfoEntry(
                255 if exists_message else 0,
                0x0004,
                0x00,
                0x00,
            )
        )

    return P3TrackInfoChunk(
        b"YP3I",
        0x02,
        0x40,
        0x0000,
        [0] * 16,
        [0] * 16,
        track_info_channel_info_entries,
        0x0004,
    )
