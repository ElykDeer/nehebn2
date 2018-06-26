#!/usr/bin/env python3

from components import ProgramState
import binaryninja as binja
import argparse
import os.path
import curses


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
    # Input Filtering
    try:
      key = stdscr.getkey()
    except curses.error as err:
      if not str(err) == "no input":
        raise curses.error(str(err))
      else:
        key = ""  # Clear Key Buffer

    # Rendering and input
    program.parseInput(key)
    program.render()
    curses.doupdate()


if __name__ == "__main__":
  background = "2a2a2a"
  text = "e0e0e0"
  curses.wrapper(main)
