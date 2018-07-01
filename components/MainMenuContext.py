from components.BinaryNinjaContext import *
from components.utils import *
import binaryninja as binja
import pyfiglet
import curses
import os


class MainMenuContext():
  def __init__(self, program, screen):
    self.program = program
    self.screen = screen
    self.welcome = pyfiglet.figlet_format('Welcome to,\n   Binary\n    Ninja', font='rowancap', width=curses.COLS)
    self.bnlogo = ''.join(open("small.logo").readlines())

    self.menupad = None
    self.menuContext = 0
    # 1 = Open
    # 2 = Options

  def parseInput(self, key):
    if self.menuContext == 0:  # Main screen
      if key == 'o' or key == 'O':  # Open File Menu
        self.menupad = None
        self.menuContext = 1
      if key == 'e' or key == 'E':  # Open File Menu
        self.menupad = None
        self.menuContext = 2

    elif self.menuContext == 1:  # Open File Menu
      if key == "KEY_F(2)":  # Main screen
        del self.filename
        self.menupad = None
        self.menuContext = 0
      else:
        if key == "KEY_BACKSPACE":
          if self.cursorIndex > 0:
            self.cursorIndex -= 1
            self.filename[self.cursorIndex] = "_"

        elif key == "\n":  # LOAD
          if os.path.isfile(''.join(self.filename[:self.cursorIndex])):
            # Load the actual program
            bv = binja.BinaryViewType.get_view_of_file(''.join(self.filename[:self.cursorIndex]), False)
            bv.update_analysis()
            while not str(bv.analysis_progress) == "Idle":
              prog = bv.analysis_progress

              self.menupad.erase()
              self.menupad.border()

              state = ''
              if prog.state == binja.AnalysisState.DisassembleState:
                state = "Disassembling"
              else:
                state = "Analyzing"
              loadingText = "Loading File"

              prog = int((prog.count/(prog.total+1))*34.0)
              self.menupad.addstr(1, int(2+(36/2)-(len(loadingText)/2)), loadingText)
              self.menupad.addstr(3, int(2+(36/2)-(len(state)/2)), state)
              self.menupad.addstr(4, 2, '[' + '#'*prog + ' '*(34-prog) + ']')
              self.menupad.refresh(0, 0, int(curses.LINES/2)-3, int(curses.COLS/2)-20, int(curses.LINES/2)+4, int(curses.COLS/2)+20)
            self.program.context = BinaryNinjaContext(self.program, self.screen, bv)
            self.program.context.parseInput(None)

          else:
            self.filename = [i for i in "File Does Not Exist_________________"]
            self.cursorIndex = 0

        elif not key == '':  # `User is Typing...``
          if self.cursorIndex < len(self.filename):
            self.filename[self.cursorIndex] = key
            self.cursorIndex += 1
            # Clear the rest of the string
            for i in range(self.cursorIndex, len(self.filename)):
              self.filename[i] = '_'

    elif self.menuContext == 2:  # Edit Option
      if key == "KEY_F(2)":  # Main screen
        self.menupad = None
        self.menuContext = 0

  def render(self):
    # TODO...seperate views into different functions
    # TODO...add some settings to the settings view
    self.screen.erase()

    self.screen.border()
    drawMultiLineText(1, 2, self.bnlogo, self.screen)
    drawMultiLineText(2, 44, self.welcome, self.screen)
    self.screen.addstr(20, 100, "UI by Elyk")

    self.screen.noutrefresh()

    if self.menuContext == 0:  # Main Menu
      if not self.menupad:
        self.menupad = curses.newpad(7, 22)
      self.menupad.erase()
      self.menupad.border()
      self.menupad.addstr(2, 2, "'O' : Open File")
      self.menupad.addstr(4, 2, "'E' : Edit Options")
      self.menupad.noutrefresh(0, 0, int(curses.LINES/2)-3, int(curses.COLS/2)-11, int(curses.LINES/2)+4, int(curses.COLS/2)+11)

    elif self.menuContext == 1:  # Open
      if not self.menupad:  # Just entering context
        self.menupad = curses.newpad(7, 40)
        self.filename = ["_"] * 36
        self.cursorIndex = 0

      self.menupad.erase()
      self.menupad.border()

      self.menupad.addstr(2, 2, "Filename: ('F2' : Back)")
      self.menupad.addstr(4, 2, ''.join(self.filename))
      self.menupad.noutrefresh(0, 0, int(curses.LINES/2)-3, int(curses.COLS/2)-20, int(curses.LINES/2)+4, int(curses.COLS/2)+20)

    elif self.menuContext == 2:  # Options
      self.menupad = curses.newpad(30, 40)

      self.menupad.erase()
      self.menupad.border()

      self.menupad.addstr(2, 2, "Options: ('F2' : Back)")
      self.menupad.noutrefresh(0, 0, int(curses.LINES/2)-7, int(curses.COLS/2)-20, int(curses.LINES/2)+23, int(curses.COLS/2)+20)
