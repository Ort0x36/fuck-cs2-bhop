<p align="center">
  <img src="https://dl.glitter-graphics.com/pub/3709/3709827od4i4nlr52.gif" alt="Bunnyhop">
</p>


# fuck-cs2-Bhop

## Overview
A python utility for automating jump actions in CS2.  
It interacts with the game's memory and allows executing bhop actions programmatically.

## Simple summary (for a layperson)

This script is an external tool that opens the game cs2.exe, finds the base address of the client.dll module, and writes values directly into the game's memory to force the character to jump (bunnyhop). Instead of sending a simulated keypress, it changes an internal game value that controls jumping.

## What it does — step by step (no heavy technical jargon)

downloads an offset (a relative memory address) from an online file;

searches for the cs2.exe process and opens a handle (a “channel” to interact with that process);

finds where client.dll is loaded in the game's memory (the base address);

when you press the spacebar, the program detects it and writes an integer to that address (dwForceJump) to toggle jumping (writes 65537 for "JUMP_ON" and 256 for "JUMP_OFF");

that write makes the game perform a jump immediately, without depending on a key event sent to the system.

## Type of memory write

It uses the Windows API function WriteProcessMemory to write integers into the target process — i.e., it directly modifies bytes inside the other process’s memory. The code has a write_int function that writes 4 or 8 bytes (and falls back to packing bytes for other sizes).

## Why not just press the spacebar?

Pressing the spacebar is possible and will make your character jump if the game has focus.

The main difference:

Physical key / sending a key event: is a system input — it affects any application that has focus. If you automate global keypresses, you might accidentally send space to other programs (chat windows, browser, etc.).

Writing into the process memory: changes only the internal state of cs2.exe. The jump happens only in the game; you’re not sending a system key, you’re changing the game’s internal data directly.

Also, for precise bunnyhop automation, writing memory lets you toggle jump state very quickly and synchronized with the game logic — something that is harder and less reliable if you only simulate keypresses.

## Important notes (responsibility / risks)

Modifying another process’s memory can be detected by anti-cheat systems and may get you banned; it’s risky in online games.

Incorrect memory writes can crash or destabilize the game.

You need permissions — the code calls OpenProcess(PROCESS_ALL_ACCESS) which requires sufficient privileges.

(It only works in windowed mode; feel free to modify it for fullscreen).

## Features
- Memory manipulation of CS2 process.
- Jump automation.
- Easy setup and execution.

## Requirements
- Python 3.9+
- psutil
- requests

## Installation
```bash
git clone https://github.com/Ort0x36/fuck-cs2-bhop.git
cd fuck-cs2-bhop
pip install -r requirements.txt
python main.py
```
