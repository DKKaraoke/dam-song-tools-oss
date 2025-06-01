from dataclasses import dataclass

from midi.time_converter import MidiTimeConverter

import mido

@dataclass
class NoteEvent:
    start_clk: int
    end_clk: int
    note: int

    def to_dict(self):
        return {
            "EndClk": self.end_clk, 
            "Note": self.note, 
            "StartClk": self.start_clk
        }

def note_event_to_midi(note_events: list[NoteEvent], port: int, channel: int, ticks_per_beat: int = 480) -> mido.MidiFile:
    """Converts NoteEvents to mido.MidiFile"""
    midi = mido.MidiFile(ticks_per_beat=ticks_per_beat)
    track = mido.MidiTrack()
    track.append(mido.MetaMessage("midi_port", port=port))
    track.append(mido.MetaMessage('set_tempo', tempo=mido.bpm2tempo(125.0)))
    
    midi.tracks.append(track)

    midi_time_converter = MidiTimeConverter()
    midi_time_converter.ticks_per_beat = ticks_per_beat
    midi_time_converter.add_tempo_change(0, 125.0)

    events = []

    for event in note_events:
        start_ticks = int(midi_time_converter.ms_to_ticks(event.start_clk))
        end_ticks = int(midi_time_converter.ms_to_ticks(event.end_clk))
        events.append((start_ticks, mido.Message("note_on", note=event.note, velocity=100, time=0, channel=channel)))
        events.append((end_ticks, mido.Message("note_off", note=event.note, velocity=100, time=0, channel=channel)))

    def insert_track_messages(track, sorted_events):
        """Sorts events and calculates delta"""
        sorted_events.sort(key=lambda x: x[0])
        last_tick = 0
        for tick, msg in sorted_events:
            msg.time = tick - last_tick
            track.append(msg)
            last_tick = tick

    insert_track_messages(track, events)

    return midi
