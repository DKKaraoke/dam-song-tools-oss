# dam-song-tools

Tools for DAM Karaoke Song data

## !! Important notes !!

This software is developed for technical research on DAM Karaoke machines.

The Karaoke song data normally recorded on DAM Karaoke machines is protected by copyright. You must handle it in accordance with your local laws and regulations.

## [Demonstration video](https://twitter.com/soltia48/status/1620095004374093824)

In this video, a song not normally included in DAM Karaoke machines, "This is an Attack," is played and scored on that machine.

## Summary

This software reads and writes DAM Karaoke machines compatible karaOKe Data (OKD) file.

## Usage

### dump-okd

Dump chunks of a OKD

```
$ dam-song-tools dump-okd --help
NAME
    dam-song-tools dump-okd - Dump chunks of a OKD

SYNOPSIS
    dam-song-tools dump-okd OKD_PATH OUTPUT_DIR_PATH

DESCRIPTION
    Dump OKD

POSITIONAL ARGUMENTS
    OKD_PATH
        Input OKD path
    OUTPUT_DIR_PATH
        Output directory path

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

### pack-okd

Pack a OKD by directly inputting a required data in each chunk

```
$ dam-song-tools pack-okd --help
NAME
    dam-song-tools pack-okd - Pack a OKD by directly inputting a required data in each chunk

SYNOPSIS
    dam-song-tools pack-okd OKD_PATH <flags> [CHUNK_PATHS]...

DESCRIPTION
    Pack OKD

POSITIONAL ARGUMENTS
    OKD_PATH
        Output OKD path
    CHUNK_PATHS
        Input chunk paths

FLAGS
    -s, --scramble=SCRAMBLE
        Default: False
        Scramble. Defaults to False.

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

### okd-to-midi

Convert a OKD to a Standard MIDI File

```
$ dam-song-tools okd-to-midi --help
NAME
    dam-song-tools okd-to-midi - Convert a OKD to a Standard MIDI File

SYNOPSIS
    dam-song-tools okd-to-midi OKD_PATH MIDI_PATH <flags>

DESCRIPTION
    Convert a OKD to a Standard MIDI File

POSITIONAL ARGUMENTS
    OKD_PATH
        Input OKD path
    MIDI_PATH
        Output MIDI path

FLAGS
    -s, --sysex_to_text=SYSEX_TO_TEXT
        Default: True
        Convert SysEx Messages to Text Meta Messages

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

### midi-to-okd

Convert a Standard MIDI File to a OKD

```
$ dam-song-tools midi-to-okd --help
NAME
    dam-song-tools midi-to-okd - Convert a Standard MIDI File to a OKD

SYNOPSIS
    dam-song-tools midi-to-okd MIDI_PATH PLAYING_OKD_PATH P3_OKD_PATH <flags>

DESCRIPTION
    Convert a Standard MIDI File to a OKD

POSITIONAL ARGUMENTS
    MIDI_PATH
        Type: str
        Input MIDI file path
    PLAYING_OKD_PATH
        Type: str
        Output Playing OKD path
    P3_OKD_PATH
        Type: str
        Output P3 OKD path

FLAGS
    -s, --scramble=SCRAMBLE
        Default: False
        Scramble. Defaults to False.

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

### dump-mtf

Dump files contained in a MTF file

```
NAME
    dam-song-tools dump-mtf - Dump files contained in a MTF file

SYNOPSIS
    dam-song-tools dump-mtf MTF_PATH OUTPUT_PATH

DESCRIPTION
    Dump files contained in a MTF file

POSITIONAL ARGUMENTS
    MTF_PATH
        Type: str
        Path to the MTF file
    OUTPUT_PATH
        Type: str
        Path to extract the archive into

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

### mtf-to-audio

Mix MTF file into "output.wav", "output.mid" files in extracted mtf folder

```
NAME
    dam-song-tools mtf-to-audio - Mix MTF file into "output.wav", "output.mid" files in extracted mtf folder.

SYNOPSIS
    dam-song-tools mtf-to-audio MTF_PATH OUTPUT_PATH <flags>

DESCRIPTION
    Mix MTF file into "output.wav", "output.mid" files in extracted mtf folder.

POSITIONAL ARGUMENTS
    MTF_PATH
        Type: str
        Path to the MTF file
    OUTPUT_PATH
        Type: str
        Path to extract the archive into, output will be saved inside

FLAGS
    -e, --export_each_file=EXPORT_EACH_FILE
        Type: bool
        Default: False
        Whether to export each individual audio file (RawADPCM → .wav, OPUS → .ogg, etc...)

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

## How to craete MIDI data for compose

### MIDI port and track map

- Port 0, Track 0-15: Instrument
- Port 1, Track 0-7,9-15: Instrument
- Port 1, Track 8: Guide melody
- Port 15, Track 0: M-Track

### P-Track

P(laying)-Track is performance data of a song.

### M-Track

M(arking)-Track includes list of hook section, two-chorus fadeout position and others.
The note map in MIDI for compose is as follows.

- Hook section: C3
- Two-chorus fadeout position: C5 (Note on alone is sufficient)

Please check [the test data](test/data/p_track.mid).

## List of verified DAM Karaoke machine

- DAM-XG5000[G,R] (LIVE DAM [(GOLD EDITION|RED TUNE)])
- DAM-XG7000[Ⅱ] (LIVE DAM STADIUM [STAGE])
- DAM-XG8000[R] (LIVE DAM Ai[R])
- DAM-XG9000 (LIVE DAM WAO!)

## Authors

- KIRISHIKI Yudai
- 東京スーパーチャンネル

## Thanks

- [Nurupo](https://github.com/gta191977649) - Author of the MIDI file ["This is an Attack"](https://github.com/gta191977649/midi_godekisenda) from which [the test data](test/data/p_track.mid) was derived

## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2024-2025 KIRISHIKI Yudai
