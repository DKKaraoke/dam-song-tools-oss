import mido


class MidiTimeConverter:
    """MIDI time converter"""

    def __init__(self):
        self.ppqn = 480
        # Tempo changes (position_ms, tempo_bpm)
        self.tempo_changes: list[tuple[int, float]] = []

    def add_tempo_change(self, position_ms: int, tempo_bpm: float):
        """Add a tempo change event at the specified position.
        
        If a tempo change already exists at the same position, it will be replaced.
        
        Parameters:
            position_ms (int): Position in milliseconds (must be >= 0)
            tempo_bpm (float): Tempo in BPM (must be > 0)
        
        Raises:
            ValueError: If position_ms is negative or tempo_bpm is not positive
        """
        if position_ms < 0:
            raise ValueError("position_ms must be non-negative")
        if tempo_bpm <= 0:
            raise ValueError("tempo_bpm must be positive")
        
        # Remove existing entry at the same position (if any)
        self.tempo_changes = [
            (pos, tempo) for pos, tempo in self.tempo_changes if pos != position_ms
        ]
        self.tempo_changes.append((position_ms, tempo_bpm))
        # Keep tempo changes sorted by position
        self.tempo_changes.sort(key=lambda x: x[0])

    def load_from_midi(self, midi: mido.MidiFile):
        """Load tempo changes from a MIDI file

        Parameters:
            midi (MidiFile): MIDI file
        """
        self.ppqn: int = midi.ticks_per_beat

        current_time_ticks = 0
        current_time_ms = 0.0
        current_tempo = 500000  # 120 BPM

        # Clear existing tempo changes
        self.tempo_changes = [(0, mido.tempo2bpm(current_tempo))]

        # Find the first track with tempo changes
        tempo_track = None
        for track in midi.tracks:
            if any(message.type == "set_tempo" for message in track):
                tempo_track = track
                break

        if tempo_track:
            for message in tempo_track:
                current_time_ticks += message.time

                # Convert current position to milliseconds
                if message.time > 0:
                    ms_per_tick = current_tempo / (self.ppqn * 1000)
                    current_time_ms += message.time * ms_per_tick

                if message.type == "set_tempo":
                    current_tempo = message.tempo
                    self.add_tempo_change(
                        round(current_time_ms), mido.tempo2bpm(current_tempo)
                    )

    def ms_to_ticks(self, time_ms: int) -> int:
        """Convert milliseconds to MIDI ticks
        
        Parameters:
            time_ms (int): Time in milliseconds (must be >= 0)
        
        Returns:
            int: Time in MIDI ticks
        
        Raises:
            ValueError: If time_ms is negative or no tempo information is available
        """
        if time_ms < 0:
            raise ValueError("time_ms must be non-negative")
        if not self.tempo_changes:
            raise ValueError("No tempo information available")

        total_ticks = 0.0

        # Handle time before first tempo change
        if time_ms < self.tempo_changes[0][0]:
            return round(self._calculate_ticks_at_tempo(time_ms, self.tempo_changes[0][1]))

        # Process each tempo section
        for i in range(len(self.tempo_changes)):
            current_tempo = self.tempo_changes[i][1]

            # Calculate end of current tempo section
            section_end = (
                self.tempo_changes[i + 1][0]
                if i < len(self.tempo_changes) - 1
                else time_ms
            )
            section_end = min(section_end, time_ms)

            # Calculate ticks for this section
            section_duration = section_end - self.tempo_changes[i][0]
            if section_duration > 0:
                total_ticks += self._calculate_ticks_at_tempo(
                    section_duration, current_tempo
                )

            if section_end == time_ms:
                break

        return round(total_ticks)

    def _calculate_ticks_at_tempo(self, duration_ms, tempo_bpm) -> float:
        """Calculate ticks for a duration at a constant tempo."""
        microseconds_per_beat = 60_000_000 / tempo_bpm
        microseconds = duration_ms * 1000
        return (microseconds / microseconds_per_beat) * self.ppqn

    def ticks_to_ms(self, ticks: int) -> int:
        """Convert MIDI ticks to milliseconds
        
        Parameters:
            ticks (int): Time in MIDI ticks (must be >= 0)
        
        Returns:
            int: Time in milliseconds
        
        Raises:
            ValueError: If ticks is negative or no tempo information is available
        """
        if ticks < 0:
            raise ValueError("ticks must be non-negative")
        if not self.tempo_changes:
            raise ValueError("No tempo information available")

        remaining_ticks = ticks
        current_time = 0

        for i in range(len(self.tempo_changes)):
            current_tempo = self.tempo_changes[i][1]

            # Calculate how many ticks until next tempo change
            if i < len(self.tempo_changes) - 1:
                section_duration = (
                    self.tempo_changes[i + 1][0] - self.tempo_changes[i][0]
                )
                section_ticks = self._calculate_ticks_at_tempo(
                    section_duration, current_tempo
                )
            else:
                section_ticks = remaining_ticks

            if remaining_ticks <= section_ticks:
                # Convert remaining ticks to ms at current tempo
                microseconds_per_beat = 60_000_000 / current_tempo
                ms = (remaining_ticks * microseconds_per_beat) / (self.ppqn * 1000)
                return round(current_time + ms)

            remaining_ticks -= section_ticks
            current_time = self.tempo_changes[i + 1][0]

        return round(current_time)
