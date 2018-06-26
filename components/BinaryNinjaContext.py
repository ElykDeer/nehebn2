from components.utils import *
import binaryninja as binja
import curses


class BinaryNinjaContext():
  """ The BinaryNinja UI """
  def __init__(self, program, screen, bv):
    self.program = program
    self.screen = screen
    self.bv = bv

    # Make Pads
    self.alertsScreen = curses.newpad(1, curses.COLS)
    self.pythonConsoleScreen = curses.newpad(1, curses.COLS)
    self.logScreen = curses.newpad(1, curses.COLS)

    self.OldCursor = 0  # Depricated
    # Disassembly Window Stuff
    self.disassemblySettings = binja.DisassemblySettings()
    self.cursor = self.bv.start  # Current p;osition in the binary
    self.cursorLDOffset = 0      # Offset from the curent cursor to the line in disassembly
    self.cursorLDSOffset = 0     # Offset (in lines) from the top of the screen to the current visual cursor in linear view
    self.cursorHSOffset = 0      # Offset (in lines) from the top of the screen to the current visual cursor in hex view
    self.disassemblyLines = []

    # Function List Pane Stuff
    self.funcListPos = 0
    self.funcListCur = 0
    self.updateFunctionList = True

    # Global Stuff
    self.focus = 0
    self.view = 0
    # 0 - Linear
    # 1 - Hex
    # 2 - CFG

    # Set up first view
    self.linearDisassemblyScreen = curses.newpad(curses.LINES-1, curses.COLS - self.program.settings["functionListScreenWidth"])
    self.functionListScreen = curses.newpad(curses.LINES-1-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
    self.xrefsScreen = curses.newpad(self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])

  def parseInput_functionList(self, key):
    bvFunctionsLen = len(self.bv.functions)
    if key == self.program.settings["functionListScrollDown"]:
      self.funcListCur += 1
    elif key == self.program.settings["functionListScrollUp"]:
      self.funcListCur -= 1
    elif key == self.program.settings["functionListPageDown"]:
      self.funcListCur += self.functionListScreen.getmaxyx()[0]-3
    elif key == self.program.settings["functionListPageUp"]:
      self.funcListCur -= self.functionListScreen.getmaxyx()[0]-3
    elif key == self.program.settings["functionListSelect"]:
      selection = self.bv.functions[self.funcListPos + self.funcListCur]
      self.cursor = selection.start
      self.cursorLDOffset = 0
      self.cursorLDSOffset = 0
      self.parseInput_linear_main(None)

    if self.funcListCur > self.functionListScreen.getmaxyx()[0]-3:
      self.funcListPos += self.funcListCur - self.functionListScreen.getmaxyx()[0]+3
      self.funcListCur = self.functionListScreen.getmaxyx()[0]-3
    elif self.funcListCur < 0:
      self.funcListPos += self.funcListCur
      self.funcListCur = 0

    if self.funcListPos < 0:
      self.funcListPos = 0
    elif self.funcListPos > bvFunctionsLen - self.functionListScreen.getmaxyx()[0]+2:
      self.funcListPos = bvFunctionsLen - self.functionListScreen.getmaxyx()[0]+2

    # TODO : Impliment Wrap Around
    # TODO : Impliment Not Crashing On Moving Past Buffer

    self.updateFunctionList = True

  def parseInput_linear_main(self, key):
    # Scroll

    # Resolve:
    #  cursor
    #  cursorLDOffset
    #  cursorLDSOffset
    if key == self.program.settings["linearDisassemblyScrollDown"]:
      disass = self.bv.get_next_linear_disassembly_lines(self.bv.get_linear_disassembly_position_at(self.cursor, self.disassemblySettings), self.disassemblySettings)
      if self.cursorLDSOffset < self.linearDisassemblyScreen.getmaxyx()[0]-3:
        self.cursorLDSOffset += 1
      if self.cursorLDOffset < len(disass):
        self.cursorLDOffset += 1
      else:
        self.cursorLDOffset = 0
    elif key == self.program.settings["linearDisassemblyScrollUp"]:
      if self.cursorLDSOffset > 0:
        self.cursorLDSOffset -= 1
      if self.cursorLDOffset > 0:
        self.cursorLDOffset -= 1
      else:
        self.cursorLDOffset = 0
    elif key == self.program.settings["linearDisassemblyPageDown"]:
      pass
    elif key == self.program.settings["linearDisassemblyPageUp"]:
      pass

    # Load Linear Disassembly to the top and bottom of the screen based off of the current linear disassembly screen offset
    curPos = self.bv.get_linear_disassembly_position_at(self.cursor, self.disassemblySettings)  # Get linear disassembly position
    bottomLines = []
    bottomLinesNeeded = self.linearDisassemblyScreen.getmaxyx()[0]-2 - self.cursorLDSOffset + self.cursorLDOffset
    while len(bottomLines) < bottomLinesNeeded:  # Load Linear Disassembly Lines To The Bottom Of The Screen
      newLines = self.bv.get_next_linear_disassembly_lines(curPos, self.disassemblySettings)
      if len(newLines) == 0:
        break
      else:
        bottomLines += newLines
    curPos = self.bv.get_linear_disassembly_position_at(self.cursor, self.disassemblySettings)  # Get linear disassembly position
    topLines = []
    topLinesNeeded = abs(self.cursorLDOffset - self.cursorLDSOffset) + self.cursorLDSOffset
    while len(topLines) < topLinesNeeded:  # Load Linear Disassembly Lines To The Top Of The Screen
      newLines = self.bv.get_previous_linear_disassembly_lines(curPos, self.disassemblySettings)
      if len(newLines) == 0:
        break
      else:
        topLines = newLines + topLines
    self.disassemblyLines = topLines + bottomLines

    if len(topLines) == 0:
      self.disassemblyLines = self.disassemblyLines[:-1*abs(len(bottomLines)-bottomLinesNeeded)]
    else:
      self.disassemblyLines = self.disassemblyLines[-1*(abs(len(bottomLines)-bottomLinesNeeded) + self.linearDisassemblyScreen.getmaxyx()[0]-2):-1*abs(len(bottomLines)-bottomLinesNeeded)]

    # Delete when done:
    self.topLines = topLinesNeeded
    self.bottomLines = bottomLinesNeeded
    # self.cursor = self.disassemblyLines[self.cursorLDSOffset].contents.address

    # #  Phase 2: Resolve Cursor Position
    # if self.cursorLDSOffset >= len(self.disassemblyLines):
    #   pass
    # elif self.cursorLDSOffset < 0:
    #   pass

    # if self.OldCursor >= self.linearDisassemblyScreen.getmaxyx()[0]-2:
    #   self.topLine += self.OldCursor - self.linearDisassemblyScreen.getmaxyx()[0]+3
    #   self.OldCursor = self.linearDisassemblyScreen.getmaxyx()[0]-3
    # if self.topLine + self.linearDisassemblyScreen.getmaxyx()[0]-2 >= len(self.disassemblyLines):  # If we've run out of lines
    #   newLines = self.bv.get_next_linear_disassembly_lines(self.pos, self.disassemblySettings)     # Load some more
    #   if len(newLines) == 0:                                                                       # Are we at the end?
    #     self.topLine = len(self.disassemblyLines) - self.linearDisassemblyScreen.getmaxyx()[0]
    #     return
    #   if len(newLines) < len(self.disassemblyLines):                                               # See if we already have these lines
    #     if self.disassemblyLines[:len(newLines)] == newLines:
    #       while len(newLines) < len(self.disassemblyLines):                                        # Load over what we already have
    #         newLines += self.bv.get_next_linear_disassembly_lines(self.pos, self.disassemblySettings)
    #   newLines = newLines[len(self.disassemblyLines):]                                             # Clip the old lines
    #   while len(newLines) <= self.linearDisassemblyScreen.getmaxyx()[0]-2:                         # Load some more lines (the visually "new" lines)
    #     newLines += self.bv.get_next_linear_disassembly_lines(self.pos, self.disassemblySettings)
    #   self.disassemblyLines = self.disassemblyLines[self.topLine:] + newLines                      # Fetch New Data
    #   self.topLine = 0
    # if self.OldCursor < 0:
    #   self.topLine += self.OldCursor
    #   self.OldCursor = 0
    #   if self.topLine < 0:
    #     newLines = self.bv.get_previous_linear_disassembly_lines(self.pos, self.disassemblySettings)
    #     if len(newLines) == 0:
    #       self.topLine = 0
    #       return
    #     if len(newLines) < len(self.disassemblyLines):                                               # See if we already have these lines
    #       if self.disassemblyLines[-len(newLines):] == newLines:
    #         while len(newLines) < len(self.disassemblyLines):                                        # Load over what we alerady have
    #           newLines = self.bv.get_previous_linear_disassembly_lines(self.pos, self.disassemblySettings) + newLines
    #     newLines = newLines[:-len(self.disassemblyLines)]                                            # Clip the old lines
    #     self.topLine += len(newLines)
    #     while self.topLine < 0:
    #       self.disassemblyLines = newLines + self.disassemblyLines
    #       newLines = self.bv.get_previous_linear_disassembly_lines(self.pos, self.disassemblySettings)
    #       self.topLine += len(newLines)
    #     self.disassemblyLines = newLines + self.disassemblyLines
    #     self.disassemblyLines = self.disassemblyLines[:self.topLine + self.linearDisassemblyScreen.getmaxyx()[0]-2]
    # self.cursor = self.disassemblyLines[self.topLine + self.OldCursor].contents.address

  def parseInput_linear(self, key):
    if self.program.settings["BinaryNinjaContextDualFocus"]:
      self.parseInput_functionList(key)
      self.parseInput_linear_main(key)
    elif self.focus == 0:
      self.parseInput_linear_main(key)
    elif self.focus == 1:
      self.parseInput_functionList(key)

  def parseInput_hex(self, key):
    # Scroll
    if key == self.program.settings["linearDisassemblyScrollDown"]:
      pass
    elif key == self.program.settings["linearDisassemblyScrollUp"]:
      pass
    elif key == self.program.settings["linearDisassemblyPageDown"]:
      pass
    elif key == self.program.settings["linearDisassemblyPageUp"]:
      pass

  def parseInput_cfg_main(self, key):
    pass

  def parseInput_cfg(self, key):
    if self.program.settings["BinaryNinjaContextDualFocus"]:
      self.parseInput_cfg_main(key)
      self.parseInput_functionList(key)
    elif self.focus == 0:
      self.parseInput_cfg_main(key)
    elif self.focus == 1:
      self.parseInput_functionList(key)

  def parseInput(self, key):
    if key == self.program.settings["BinaryNinjaContextSwitchView"]:
      # Clean Up
      if self.view == 0:
        del self.linearDisassemblyScreen
        del self.functionListScreen
        del self.xrefsScreen
      elif self.view == 1:
        del self.hexScreen
      elif self.view == 2:
        del self.cfgScreen
        del self.functionListScreen
        del self.xrefsScreen

      # Switch Contexts
      if self.view == 0:
        self.view = 1
      elif self.view == 1:
        self.view = 2
      elif self.view == 2:
        self.view = 0

      # Setup
      if self.view == 0:
        self.updateFunctionList = True
        self.linearDisassemblyScreen = curses.newpad(curses.LINES-1, curses.COLS - self.program.settings["functionListScreenWidth"])
        self.functionListScreen = curses.newpad(curses.LINES-1-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
        self.xrefsScreen = curses.newpad(self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
      elif self.view == 1:
        self.updateFunctionList = True
        self.hexScreen = curses.newpad(curses.LINES-1, curses.COLS)
      elif self.view == 2:
        self.cfgScreen = curses.newpad(curses.LINES-1, curses.COLS - self.program.settings["functionListScreenWidth"])
        self.functionListScreen = curses.newpad(curses.LINES-1-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
        self.xrefsScreen = curses.newpad(self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])

    elif key == self.program.settings["BinaryNinjaContextSwitchFocus"]:
      if self.focus == 0:
        self.focus = 1
      elif self.focus == 1:
        self.focus = 2
      elif self.focus == 2:
        self.focus = 0

    if self.view == 0:
      self.parseInput_linear(key)
    elif self.view == 1:
      self.parseInput_hex(key)
    elif self.view == 2:
      self.parseInput_cfg(key)

  def render_functionList(self):
    # Not the best implimentation of this...but it makes only the functionList window input-lag (unless in dual focus mode... :/ )
    # TODO Fix
    if self.updateFunctionList:
      self.functionListScreen.erase()

    if self.focus == 1 and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.functionListScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.functionListScreen.border()

    if self.updateFunctionList:
      for yLine in range(self.funcListPos, self.funcListPos+(curses.LINES-3)-self.program.settings["xrefsScreenHeight"]):
        if yLine == self.funcListCur + self.funcListPos:
          # TODO Turn into line highlight instead, sift text back over to the left
          self.functionListScreen.addstr(yLine-self.funcListPos+1, 2, '> ' + self.bv.functions[yLine].name)  # Name access is slow
        else:
          self.functionListScreen.addstr(yLine-self.funcListPos+1, 4, self.bv.functions[yLine].name)  # Name access is slow
      self.updateFunctionList = False

    self.functionListScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])

  def render_xrefs(self):
    self.xrefsScreen.erase()
    if self.focus == 2 and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.xrefsScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.xrefsScreen.border()

    drawMultiLineText(1, 1, "XRefs", self.xrefsScreen)
    self.xrefsScreen.noutrefresh(0, 0, curses.LINES-1-self.program.settings["xrefsScreenHeight"], 0, curses.LINES-2, self.program.settings["functionListScreenWidth"])

  def render_linear(self):
    self.render_functionList()
    self.render_xrefs()

    self.linearDisassemblyScreen.erase()
    if self.focus == 0 and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.linearDisassemblyScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.linearDisassemblyScreen.border()

    try:
      for yLine, textLine in zip(range(len(self.disassemblyLines)), self.disassemblyLines):
        if yLine == self.cursorLDSOffset:
          # TODO Turn into line highlight instead, sift text back over to the left
          self.linearDisassemblyScreen.addstr(yLine+1, 1, '>' + str(textLine))
        else:
          self.linearDisassemblyScreen.addstr(yLine+1, 2, str(textLine))
    except:
      pass
      # import pdb
      # pdb.set_trace()
    self.linearDisassemblyScreen.noutrefresh(0, 0, 0, self.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

  def render_hex(self):
    self.hexScreen.erase()
    self.hexScreen.border()

    drawMultiLineText(1, 1, "Hex View", self.hexScreen)

    self.hexScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2, curses.COLS-1)

  def render_cfg(self):
    self.render_functionList()
    self.render_xrefs()

    self.cfgScreen.erase()
    if self.focus == 0 and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.cfgScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.cfgScreen.border()

    drawMultiLineText(1, 1, "Control Flow Graph!", self.cfgScreen)
    self.cfgScreen.noutrefresh(0, 0, 0, self.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

  def render_alerts(self):
    self.alertsScreen.erase()

    self.alertsScreen.addstr(0, 0, str(self.bv))
    try:
      self.alertsScreen.addstr(0, 60, "Disass Lines: " + str(len(self.disassemblyLines)))
      self.alertsScreen.addstr(0, 80, "Cursor: " + hex(self.cursor))
      self.alertsScreen.addstr(0, 100, "Toplines: " + str(self.topLines))
      self.alertsScreen.addstr(0, 120, "BottomLines: " + str(self.bottomLines))
      # self.alertsScreen.addstr(0, 100, "Toplines: " + hex(len(self.topLines)))
      # self.alertsScreen.addstr(0, 120, "BottomLines: " + hex(len(self.bottomLines)))
      self.alertsScreen.addstr(0, 140, "Pos: " + str(self.cursorLDOffset))
      # self.alertsScreen.addstr(0, 100, "Selection: " + self.selll.name)
      # self.alertsScreen.addstr(0, 80, "Screen Height: " + str(self.linearDisassemblyScreen.getmaxyx()[0]-2))
    except:
      pass
    self.alertsScreen.noutrefresh(0, 0, curses.LINES-1, 0, curses.LINES-1, curses.COLS-1)

  def render(self):
    if self.view == 0:
      self.render_linear()
    elif self.view == 1:
      self.render_hex()
    elif self.view == 2:
      self.render_cfg()

    self.render_alerts()
