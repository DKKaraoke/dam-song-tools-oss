import numpy as np
import configparser
import io
from pydub import AudioSegment
from okd.adpcm import AdpcmDecoder

SETTING_FILE = "settings.ini"

class MtfAudio:
    """MTF Audio Processor Class"""

    def decode_adpcm(self, input_file):
        """Decodes ADPCM to AudioSegment"""
        with open(input_file, "rb") as f:
            data = f.read()

        stream = io.BytesIO(data)
        decoder = AdpcmDecoder()
        samples = decoder.decode(stream)
        samples = np.array(samples, dtype="int16")

        self.audio = AudioSegment(samples.tobytes(), frame_rate=22050, sample_width=2, channels=1)

    def decode_opus(self, input_file):
        """Loads OPUS(OGG), converts it to AudioSegment and adjust volume"""
        audio = AudioSegment.from_file(input_file)
        self.audio = audio + self.load_opus_volume_increase()  # Adjust volume from settings file

    def load_opus_volume_increase(self):
        """Loads Volume settings from ini"""
        config = configparser.ConfigParser()
        config.read(SETTING_FILE)
        return int(config.get("MtfAudio", "OpusVolumeIncrease", fallback=0))

    def decode_others(self, input_file):
        """Loads Audio File, converts it to AudioSegment"""
        self.audio = AudioSegment.from_file(input_file)

    def apply_vol_events(self, vol_events, start_time):
        """Applies VolEvent"""
        for evt_type in ["Velocity", "Pan", "AdpcmVol", "RelVol", "RecBoostVol", "AdpcmRev"]:
            self.audio = self.process_vol_events(vol_events, start_time, evt_type)
        return self.audio

    def process_vol_events(self, vol_events, start_time, apply_type):
        """Processes audio VolEvent"""
        # Initial Values
        value_map = {
            "Velocity": 1.0,
            "Pan": 0.0,
            "AdpcmVol": 1.0,
            "RelVol": 1.0,
            "RecBoostVol": 0.0,  # dB
            "AdpcmRev": 0        # Not Implemented
        }
        apply_value = value_map.get(apply_type)

        # Applies VolEvents before start_time
        for event in sorted(vol_events, key=lambda e: e["clock"]):
            if event["clock"] > start_time:
                break
            if event["type"] == apply_type:
                if apply_type in ["Velocity", "AdpcmVol", "RelVol"]:
                    apply_value = event["value"] / 127.0
                elif apply_type == "Pan":
                    apply_value = (event["value"] / 100.0) if -100 <= event["value"] <= 100 else 0
                elif apply_type == "RecBoostVol":
                    apply_value = event["value"]
                elif apply_type == "AdpcmRev":
                    apply_value = event["value"]

        audio = self.apply_effect(self.audio, apply_type, apply_value)

        # Applies VolEvents after start_time
        for event in sorted(vol_events, key=lambda e: e["clock"]):
            if event["clock"] < start_time or event["type"] != apply_type:
                continue

            rel_time = event["clock"] - start_time
            if apply_type in ["Velocity", "AdpcmVol", "RelVol"]:
                apply_value = event["value"] / 127.0
            elif apply_type == "Pan":
                apply_value = (event["value"] / 100.0) if -100 <= event["value"] <= 100 else 0
            elif apply_type == "RecBoostVol":
                apply_value = event["value"]
            elif apply_type == "AdpcmRev":
                apply_value = event["value"]

            segment = self.audio[rel_time:]
            segment = self.apply_effect(segment, apply_type, apply_value)
            audio = audio[:rel_time] + segment

        return audio

    def apply_effect(self, segment, effect_type, value):
        """Applies an Effect"""
        if effect_type == "Velocity":
            if value <= 0:
                return segment - 120  # mute
            gain = 20 * np.log10(value)
            return segment + gain
        elif effect_type == "Pan":
            return segment.pan(value)
        elif effect_type == "AdpcmVol":
            if value <= 0:
                return segment - 120
            gain = 20 * np.log10(value)
            return segment + gain
        elif effect_type == "RelVol":
            if value <= 0:
                return segment - 120
            gain = 20 * np.log10(value)
            return segment + gain
        elif effect_type == "RecBoostVol":
            return segment - value
        return segment
