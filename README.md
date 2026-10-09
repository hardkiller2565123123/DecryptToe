# DecryptToe

DecryptToe is a simple Windows tool for inspecting and dumping game executables from memory.

It's mainly intended for reverse engineering, debugging, and researching packed or encrypted games. It lets you launch a game, wait for it to load, and capture its executable image for further analysis in tools like IDA or Ghidra.

## Usage

1. Download the latest version from **Releases**.
2. Open `DecryptToe.exe`.
3. Select your game's executable.
4. Set the dump timer (120 seconds by default).
5. Click **Launch & Dump**.
6. Find the dumped files in your selected output folder.

## Limitations

- Not every game can be successfully dumped or decrypted.
- Some games use additional encryption or protection.
- Dumped executables may require further fixes before they can be used.
- Anti-cheat and protected processes are not supported.
- Memory dumping does not guarantee a fully working executable.

## Disclaimer

DecryptToe is intended for educational purposes, debugging, reverse engineering, and game preservation.

No game files or copyrighted content are included.
