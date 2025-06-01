from logging import getLogger

import tarfile
import os
import io
import mido
import json
import shutil
from pydub import AudioSegment

from mtf import MtfAudio
from mtf import note_events_conversion
from mtf.note_events_conversion import NoteEvent
from mtf import saiten_ref_conversion
from mtf.saiten_ref_conversion import SaitenRefEvent
from mtf.saiten_ref_conversion import SaitenRefEventType

__logger = getLogger(__name__)

class MtfFileContent:
    PLAYLIST_FILES: dict = {
        "PlayListDrum0.json": "Drum",
        "PlayListUpper0.json": "Upper",
        "PlayListGuideMelo0.json": "GuideMelody",
        "PlayListSynthChorus0.json": "SynthChorus",
        "PlayListMusic0.json": "MixedMusic",
        "PlayListChorus0.json": "AdpcmChorus",
        "PlayListGuideVocal00.json": "GuideVocal",
        "PlayListGuideVocal10.json": "GuideVocalMale",
        "PlayListGuideVocal20.json": "GuideVocalFemale",
    }

    SONG_PROPERTY_FILE: str = "SongProperty.json"

    REF_FILES: dict = {
        "RefGuideMelo.json": {"description": "GuideMelody", "port": 0, "channel": 0}, # Port 0 Channel 0 (Not compatible with OKD)
        "RefChorus.json": {"description": "Chorus", "port": 0, "channel": 1}, # Port 0 Channel 1 (Not compatible with OKD)
        "RefGuideVocal0.json": {"description": "GuideVocal", "port": 0, "channel": 2}, # Port 0 Channel 2 (Not compatible with OKD)
        "RefGuideVocal1.json": {"description": "GuideVocalMale", "port": 0, "channel": 3}, # Port 0 Channel 3 (Not compatible with OKD)
        "RefGuideVocal2.json": {"description": "GuideVocalFemale", "port": 0, "channel": 4}, # Port 0 Channel 4 (Not compatible with OKD)
    }

def extract_mtf(mtf_path: str, output_path: str) -> str:
    """Extracts MTF file to output_path"""
    with open(mtf_path, "rb") as f:
        data = bytearray(f.read())
    data[0:4] = b"\x1f\x8b\x08\x00" # GZip header

    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        tar.extractall(path=output_path)
        members = tar.getmembers()
        root_folder_name = members[0].name.split('/')[0] if members else ''

    if not root_folder_name:
        __logger.error(f"Failed to detect root folder in archive.")
        return

    mtf_root_path = os.path.join(output_path, root_folder_name, 'mtf')

    return mtf_root_path

def dump_playlist(mtf_root_path: str, export_each_file: bool = False) -> str:
    """Reads PlayList JSON files, parses them and converts to a WAV file"""
    mixed_audio = AudioSegment.silent(duration=0)
    for playlist_file in MtfFileContent.PLAYLIST_FILES:
        json_path = os.path.join(mtf_root_path, playlist_file)
        if not os.path.exists(json_path):
            __logger.info(f"{MtfFileContent.PLAYLIST_FILES[playlist_file]} track not found, skipping.")
            continue

        with open(json_path, "r", encoding="utf-8") as f:
            playlist = json.load(f)

        vol_events = playlist.get("VolEvent", [])

        for item in playlist.get("AudioPlayListItem", []):
            file_name = item["file"]
            start_time = item["start_clk"] # ms
            input_path = os.path.join(mtf_root_path, file_name)

            mtf_audio_processor = MtfAudio()

            if item["codec"] == "RawADPCM":
                if os.path.exists(input_path):
                    audio = mtf_audio_processor.decode_adpcm(input_path)
                    audio = mtf_audio_processor.apply_vol_events(vol_events, start_time)

                    if export_each_file:
                        adpcm_output_path = input_path + '.wav'
                        audio.export(adpcm_output_path, format='wav')
                else:
                    __logger.warning(f"{input_path} not found, skipping.")
                    continue
            elif item["codec"] == "OPUS":
                if os.path.exists(input_path):
                    audio = mtf_audio_processor.decode_opus(input_path)
                    audio = mtf_audio_processor.apply_vol_events(vol_events, start_time)

                    if export_each_file:
                        ogg_output_path = input_path + '.ogg'
                        shutil.copy(input_path, ogg_output_path)
                else:
                    __logger.warning(f"{input_path} not found, skipping.")
                    continue
            elif item["codec"] == "MP3":
                if os.path.exists(input_path):
                    audio = mtf_audio_processor.decode_others(input_path)
                    audio = mtf_audio_processor.apply_vol_events(vol_events, start_time)

                    if export_each_file:
                        mp3_output_path = input_path + '.mp3'
                        shutil.copy(input_path, mp3_output_path)
                else:
                    __logger.warning(f"{input_path} not found, skipping.")
                    continue
            elif item["codec"] == "AAC":
                if os.path.exists(input_path):
                    audio = mtf_audio_processor.decode_others(input_path)
                    audio = mtf_audio_processor.apply_vol_events(vol_events, start_time)

                    if export_each_file:
                        aac_output_path = input_path + '.aac'
                        shutil.copy(input_path, aac_output_path)
                else:
                    __logger.warning(f"{input_path} not found, skipping.")
                    continue
            elif item["codec"] == "FLAC":
                if os.path.exists(input_path):
                    audio = mtf_audio_processor.decode_others(input_path)
                    audio = mtf_audio_processor.apply_vol_events(vol_events, start_time)

                    if export_each_file:
                        flac_output_path = input_path + '.flac'
                        shutil.copy(input_path, flac_output_path)
                else:
                    __logger.warning(f"{input_path} not found, skipping.")
                    continue
            else:
                __logger.warning(f"Unsupported codec {item['codec']}, skipping.")
                continue

            # MIX
            if len(mixed_audio) < start_time + len(audio):
                mixed_audio = mixed_audio.append(AudioSegment.silent(duration=start_time + len(audio) - len(mixed_audio)), crossfade=0)
            mixed_audio = mixed_audio.overlay(audio, position=int(start_time))

    # Export to a WAV file
    final_output_path = os.path.join(mtf_root_path, "output.wav")
    mixed_audio.export(final_output_path, format="wav")
    __logger.info(f"Mixed WAV file saved at: {final_output_path}")

    return final_output_path

def dump_refs(mtf_root_path: str, export_each_file: bool = False) -> str:
    """Dump refs to a SMF file"""
    # Prepare MidiFile
    midi = mido.MidiFile(ticks_per_beat=480)

    # Dump SaitenRef
    saiten_ref_midi = dump_saiten_ref(mtf_root_path, export_each_file)
    for track in saiten_ref_midi.tracks:
        midi.tracks.append(track)

    # Dump Ref JSON files
    for ref_file in MtfFileContent.REF_FILES:
        ref_midi = dump_ref(mtf_root_path, ref_file)
        if ref_midi is None:
            continue
        for track in ref_midi.tracks:
            midi.tracks.append(track)

    # Export to a SMF file
    final_output_path = os.path.join(mtf_root_path, "output.mid")
    midi.save(final_output_path)
    __logger.info(f"Mixed SMF file saved at: {final_output_path}")

    return final_output_path

def dump_saiten_ref(mtf_root_path: str, export_each_file: bool = False) -> mido.MidiFile:
    """Dump SaitenRef"""
    json_path = os.path.join(mtf_root_path, MtfFileContent.SONG_PROPERTY_FILE)

    with open(json_path, "r", encoding="utf-8") as f:
        song_property = json.load(f)

    saiten_ref_events: list[NoteEvent] = []

    for item in song_property.get("SaitenRef", []):
        saiten_ref_event = SaitenRefEvent(
            item["Clock"], SaitenRefEventType.value_of(item["msg"][0]), item["msg"][1], item["msg"][2]
        )
        saiten_ref_events.append(saiten_ref_event)

    saiten_ref_midi = saiten_ref_conversion.saiten_ref_to_midi(saiten_ref_events)
    if export_each_file:
        saiten_ref_midi_output_path = os.path.join(mtf_root_path, MtfFileContent.SONG_PROPERTY_FILE + ".mid")
        saiten_ref_midi.save(saiten_ref_midi_output_path)

    return saiten_ref_midi

def dump_ref(mtf_root_path: str, ref_file: str, export_each_file: bool = False) -> mido.MidiFile:
    """Dump Ref"""
    json_path = os.path.join(mtf_root_path, ref_file)
    if not os.path.exists(json_path):
        __logger.info(f"{MtfFileContent.REF_FILES[ref_file]["description"]} ref not found, skipping.")
        return None

    with open(json_path, "r", encoding="utf-8") as f:
        ref = json.load(f)

    note_events: list[NoteEvent] = []

    for item in ref.get("Pitch", []):
        note_event = NoteEvent(item["StartClk"], item["EndClk"], item["Note"])
        note_events.append(note_event)

    ref_midi = note_events_conversion.note_event_to_midi(note_events, MtfFileContent.REF_FILES[ref_file]["port"], MtfFileContent.REF_FILES[ref_file]["channel"])
    if export_each_file:
        ref_midi_output_path = json_path + ".mid"
        ref_midi.save(ref_midi_output_path)
    return ref_midi