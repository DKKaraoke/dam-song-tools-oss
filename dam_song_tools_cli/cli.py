import dataclasses
import fire
import logging
import mido
import numpy as np
import os
import json
import soundfile as sf
from typing import Any

from okd import (
    YksOkdHeader,
    OkdFile,
    GenericChunk,
    YkyiChunk,
    MTrackInterpretation,
    MTrackChunk,
    PTrackInfoChunk,
    ExtendedPTrackInfoChunk,
    P3TrackInfoChunk,
    PTrackChunk,
    AdpcmChunk,
    okd_to_midi,
    midi_to_okds,
)

from mtf import mtf_conversion

def default(item: Any):
    match item:
        case bytes():
            return item.hex(" ").upper()
        case _ if dataclasses.is_dataclass(item):
            return dataclasses.asdict(item)
        case _:
            raise TypeError(type(item))


class Cli:
    """DAM OKD Tools CLI

    Args:
        log_level (str, optional): Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}
    """

    @staticmethod
    def __config_logger(level: str) -> None:
        """Config logger

        Args:
            level (str): Log level
        """

        logging.basicConfig(
            level=level,
            format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
        )

    def __init__(self, log_level="INFO"):
        """DAM OKD Tools CLI

        Args:
            log_level (str, optional): Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}
        """

        Cli.__config_logger(log_level)
        self.__logger = logging.getLogger(__name__)

    def song_info(self, okd_path, output_json: bool = False) -> None:
        """Show song information (YKYI chunk) from a OKD file

        Args:
            okd_path (str): Input OKD path
            output_json (bool): Output as JSON format. Defaults to False.

        Raises:
            ValueError: Argument `okd_path` must be str.
        """

        if not isinstance(okd_path, str):
            raise ValueError("Argument `okd_path` must be str.")

        with open(okd_path, "rb") as okd_file:
            okd_file = OkdFile.read(okd_file)

            ykyi_chunk = None
            for chunk in okd_file.chunks:
                if isinstance(chunk, YkyiChunk):
                    ykyi_chunk = chunk
                    break

            if ykyi_chunk is None:
                print("YKYI chunk not found in the OKD file.")
                return

            if output_json:
                output = json.dumps(
                    ykyi_chunk.to_json_serializable(),
                    indent=2,
                    ensure_ascii=False,
                )
                print(output)
            else:
                print("=" * 50)
                print("楽曲情報 (Song Information)")
                print("=" * 50)
                for entry in ykyi_chunk.entries:
                    if entry.key:
                        print(f"{entry.key}: {entry.value}")
                    else:
                        print(f"  {entry.value}")
                print("=" * 50)

    def dump_okd(self, okd_path, output_dir_path) -> None:
        """Dump chunks of a OKD

        Args:
            okd_path (str): Input OKD path
            output_dir_path (str): Output directory path

        Raises:
            ValueError: Argument `okd_path` must be str.
            ValueError: Argument `output_directory_path` must be str.
        """

        if not isinstance(okd_path, str):
            raise ValueError("Argument `okd_path` must be str.")
        if not isinstance(output_dir_path, str):
            raise ValueError("Argument `output_directory_path` must be str.")

        os.makedirs(output_dir_path, exist_ok=True)

        with open(okd_path, "rb") as okd_file:
            okd_file = OkdFile.read(okd_file)
            self.__logger.info(f"OKD loaded. header={okd_file.header}")

            for chunk in okd_file.chunks:
                chunk_id_hex = chunk.id.hex().upper()
                self.__logger.info(
                    f"{type(chunk).__name__} found. id={chunk.id} (0x{chunk_id_hex})"
                )
                if isinstance(chunk, GenericChunk):
                    output_path = os.path.join(
                        output_dir_path,
                        "chunk_0x" + chunk.id.hex().upper() + ".bin",
                    )
                    with open(output_path, "wb") as output_file:
                        output_file.write(chunk.id)
                        output_file.write(chunk.payload)
                elif isinstance(chunk, YkyiChunk):
                    output_path = os.path.join(output_dir_path, "ykyi_info.json")
                    output_json = json.dumps(
                        chunk.to_json_serializable(),
                        indent=2,
                        ensure_ascii=False,
                    )
                    with open(output_path, "w", encoding="utf-8") as output_file:
                        output_file.write(output_json)
                elif isinstance(chunk, MTrackChunk):
                    m_track_interpritation = MTrackInterpretation.from_track(chunk)

                    track_number = chunk.id[3]
                    output_path = os.path.join(
                        output_dir_path, "m_track_" + str(track_number) + ".json"
                    )
                    output_json = json.dumps(
                        chunk.to_json_serializable(),
                        indent=2,
                    )
                    with open(output_path, "w") as output_file:
                        output_file.write(output_json)

                    output_path = os.path.join(
                        output_dir_path,
                        "m_track_interpretation_" + str(track_number) + ".json",
                    )
                    output_json = json.dumps(
                        m_track_interpritation,
                        indent=2,
                        default=default,
                    )
                    with open(output_path, "w") as output_file:
                        output_file.write(output_json)
                elif isinstance(chunk, PTrackInfoChunk):
                    output_path = os.path.join(output_dir_path, "p_track_info.json")
                    output_json = json.dumps(
                        chunk,
                        indent=2,
                        default=default,
                    )
                    with open(output_path, "w") as output_file:
                        output_file.write(output_json)
                elif isinstance(chunk, ExtendedPTrackInfoChunk):
                    output_path = os.path.join(
                        output_dir_path, "extended_p_track_info.json"
                    )
                    output_json = json.dumps(
                        chunk,
                        indent=2,
                        default=default,
                    )
                    with open(output_path, "w") as output_file:
                        output_file.write(output_json)
                elif isinstance(chunk, P3TrackInfoChunk):
                    output_path = os.path.join(output_dir_path, "p3_track_info.json")
                    output_json = json.dumps(
                        chunk,
                        indent=2,
                        default=default,
                    )
                    with open(output_path, "w") as output_file:
                        output_file.write(output_json)
                elif isinstance(chunk, PTrackChunk):
                    track_number = chunk.id[3]
                    output_path = os.path.join(
                        output_dir_path, "p_track_" + str(track_number) + ".json"
                    )
                    output_json = json.dumps(
                        chunk.to_json_serializable(),
                        indent=2,
                    )
                    with open(output_path, "w") as output_file:
                        output_file.write(output_json)
                elif isinstance(chunk, AdpcmChunk):
                    for i, track in enumerate(chunk.tracks):
                        output_path = os.path.join(output_dir_path, f"adpcm_{i}.wav")
                        samples = track.decode()
                        samples = np.array(samples, "int16")
                        sf.write(output_path, samples, 22050)
                else:
                    self.__logger.error("Unknown chunk type detected.")

    def pack_okd(self, okd_path, *chunk_paths, scramble=False):
        """Pack a OKD by directly inputting the required data in chunks

        Args:
            okd_path (str): Output OKD path
            chunk_paths (*str): Input chunk paths
            scramble (bool, optional): Scramble. Defaults to False.

        Raises:
            ValueError: Argument `okd_path` must be str.
            ValueError: Argument `chunk_paths` must be *str.
            ValueError: Argument `scramble` must be bool.
        """

        if not isinstance(okd_path, str):
            raise ValueError("Argument `output` must be str.")
        if not isinstance(scramble, bool):
            raise ValueError("Argument `scramble` must be bool.")

        for chunk_path in chunk_paths:
            if not isinstance(chunk_path, str):
                raise ValueError("Argument `input` must be *str.")

            chunks: list[GenericChunk] = []
            with open(chunk_path, "rb") as input_file:
                chunk = GenericChunk.read(input_file)
                chunk_id_hex = chunk.id.hex().upper()
                self.__logger.info(f"Add chunk {id} (0x{chunk_id_hex}).")
                chunks.append(chunk)

        header = YksOkdHeader(0, "YKS-1   v6.0v110", 0, 0, 0)
        self.__logger.info(f"Set header. header={header}")
        okd = OkdFile(header, chunks)
        with open(okd_path, "wb") as output_file:
            okd.write(output_file, scramble)

    def okd_to_midi(self, okd_path, midi_path, sysex_to_text=True) -> None:
        """Convert a OKD to a Standard MIDI File

        Args:
            okd_path (str): Input OKD path
            midi_path (str): Output MIDI path
            sysex_to_text (bool): Convert SysEx Messages to Text Meta Messages

        Raises:
            ValueError: Argument `okd_path` must be str.
            ValueError: Argument `midi_path` must be str.
        """

        if not isinstance(okd_path, str):
            raise ValueError("Argument `okd_path` must be str.")
        if not isinstance(midi_path, str):
            raise ValueError("Argument `midi_path` must be str.")
        if not isinstance(sysex_to_text, bool):
            raise ValueError("Argument `sysex_to_text` must be bool.")

        with open(okd_path, "rb") as okd_file:
            okd = OkdFile.read(okd_file)
            midi = okd_to_midi(okd, sysex_to_text)
            midi.save(midi_path)

    def midi_to_okd(
        self, midi_path: str, playing_okd_path: str, p3_okd_path: str, scramble=False
    ) -> None:
        """Convert a Standard MIDI File to a OKD

        Args:
            midi_path (str): Input MIDI file path
            playing_okd_path (str): Output Playing OKD path
            p3_okd_path (str): Output P3 OKD path
            scramble (bool, optional): Scramble. Defaults to False.

        Raises:
            ValueError: Argument `midi_path` must be str.
            ValueError: Argument `playing_okd_path` must be str.
            ValueError: Argument `p3_okd_path` must be str.
            ValueError: Argument `scramble` must be bool.
        """

        if not isinstance(midi_path, str):
            raise ValueError("Argument `midi_path` must be str.")
        if not isinstance(playing_okd_path, str):
            raise ValueError("Argument `playing_okd_path` must be str.")
        if not isinstance(p3_okd_path, str):
            raise ValueError("Argument `p3_okd_path` must be str.")
        if not isinstance(scramble, bool):
            raise ValueError("Argument `scramble` must be bool.")

        midi = mido.MidiFile(midi_path)
        header = YksOkdHeader(0, "YKS-1   v6.0v110", 0, 0, 0)
        self.__logger.info(f"Set header. header={header}")
        playing_okd, p3_okd = midi_to_okds(midi, header)
        with open(playing_okd_path, "wb") as playing_okd_file:
            self.__logger.info("Write Playing OKD.")
            playing_okd.write(playing_okd_file, scramble)
        with open(p3_okd_path, "wb") as p3_okd_file:
            self.__logger.info("Write P3 OKD.")
            p3_okd.write(p3_okd_file, scramble)
    
    def dump_mtf(self, mtf_path: str, output_path: str):
        """Dump files contained in a MTF file
        
        Args:
            mtf_path (str): Path to the MTF file
            output_path (str): Path to extract the archive into
        """
        mtf_conversion.extract_mtf(mtf_path, output_path)

    def mtf_to_audio(self, mtf_path: str, output_path: str, export_each_file: bool = False):
        """Mix MTF file into "output.wav", "output.mid" files in extracted mtf folder.

        Args:
            mtf_path (str): Path to the MTF file
            output_path (str): Path to extract the archive into, output will be saved inside
            export_each_file (bool): Whether to export each individual audio file (RawADPCM → .wav, OPUS → .ogg, etc...)
        """
        mtf_root_path = mtf_conversion.extract_mtf(mtf_path, output_path)
        mtf_conversion.dump_playlist(mtf_root_path, export_each_file)
        mtf_conversion.dump_refs(mtf_root_path, export_each_file)


def main() -> None:
    fire.Fire(Cli)


if __name__ == "__main__":
    main()
