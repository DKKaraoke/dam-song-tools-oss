from typing import Union

from .chunk_base import ChunkBase
from .generic_chunk import GenericChunk

from .ykyi_chunk import YkyiChunk
from .p_track_info_chunk import PTrackInfoChunk
from .p3_track_info_chunk import P3TrackInfoChunk
from .extended_p_track_info_chunk import ExtendedPTrackInfoChunk
from .m_track_chunk import MTrackChunk
from .p_track_chunk import PTrackChunk
from .adpcm_chunk import AdpcmChunk

OkdChunk = Union[
    ChunkBase,
    GenericChunk,
    YkyiChunk,
    PTrackInfoChunk,
    P3TrackInfoChunk,
    ExtendedPTrackInfoChunk,
    MTrackChunk,
    PTrackChunk,
    AdpcmChunk,
]
