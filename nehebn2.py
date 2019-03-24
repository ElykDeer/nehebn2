#!/usr/bin/env python3

from components import ProgramState
import binaryninja as binja
import argparse
import os.path
import curses

# TODO...implement live-refreashing the settings.json during run (add the keybinding and check for it here in the global input loop)
# TODO...support multi-key presses? Not sure if this already works or not
# TODO...make sure to support small terminals (I think it does right now, but I should add some more checks so nothing goes out of bounds)

def main(stdscr):
  # Setup
  parser = argparse.ArgumentParser(description='Nearly Headless BinaryNinja.')
  parser.add_argument('filename', nargs='?', default="")
  args = parser.parse_args()

  program = ''
  if not args.filename == "":
    if os.path.isfile(args.filename):

      bv = binja.BinaryViewType.get_view_of_file(''.join(args.filename), False)
      bv.update_analysis()
      while not str(bv.analysis_progress) == "Idle":
        prog = bv.analysis_progress

        stdscr.erase()
        stdscr.border()

        state = ''
        if prog.state == binja.AnalysisState.DisassembleState:
          state = "Disassembling"
        else:
          state = "Analyzing"
        loadingText = "Loading File: "

        prog = int((prog.count/(prog.total+1))*34.0)
        stdscr.addstr(2, 4, loadingText)
        stdscr.addstr(2, 4 + len(loadingText), state)
        stdscr.addstr(4, 4, '[' + '#'*prog + ' '*(34-prog) + ']')
        stdscr.refresh()
      program = ProgramState(stdscr, bv)
    else:
      raise IOError("File does not exist.")
  else:
    program = ProgramState(stdscr)

  key = ""
  while program.is_running:
    # Input Filtering, Debuffering, Processing
    count = 0
    while count < 5:
      try:
        key = stdscr.getkey()
        program.parseInput(key)
        count += 1
      except curses.error as err:
        if not str(err) == "no input":
          raise curses.error(str(err))
        else:
          key = ""  # Clear Key Buffer
          break

    # Render
    program.render()
    curses.doupdate()


if __name__ == "__main__":
  background = "2a2a2a"
  text = "e0e0e0"
  curses.wrapper(main)
