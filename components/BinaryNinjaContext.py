from components.utils import drawList, drawMultiLineText
import binaryninja as binja
import curses


# TODO...Loosely ordered by importance:
# TODO...impliment 'GO TO' box
# TODO...maybe seperate each view into a class to make cleaning up the various view-dependant variables neater?
# TODO...impliment color themes with the new color theme format courtesy of peter
# TODO...impliment disassembly options
# TODO...impliment scroll bars on windows?, and the setting to disable them
# TODO...impliment the ability to edit what we're seeing.. Enter an insert mode in Hex view (or be in it by defualt like in BN proper), and have patches availible in linear/cfg
# TODO...impliment the ability to cursor into linear assembly lines.
# TODO...impliment undo!  I think the API actually takes care of this for us nicely, but editing has to be implimented first and it'd be nice to snap the view back to whatever is being edited too


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

    # Disassembly Window Stuff
    self.disassemblySettings = binja.DisassemblySettings()
    
    self.pos = self.bv.start     # Current position in the binary
    self.posOffset = 0           # Displacement in lines between the top of the screen and the rendered location of self.pos
    self.cursorOffset = 0        # Offset (in lines) from the top of the screen to the current visual cursor in linear view
    self.disassemblyLines = []   # TODO...make sure this is deleted in the view's cleanup

    self.hexOffset = 0           # Offset (in lines) from the top of the screen to the current visual cursor in hex view
    self.br = binja.BinaryReader(bv)
    self.hexLines = []           # TODO...make sure this is deleted in the view's cleanup

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
    self.loadLinearDisassembly()

  def loadLinearDisassembly(self):
    # Get current offset into block
    disassBlockOffset = 0
    for line in self.bv.get_next_linear_disassembly_lines(self.bv.get_linear_disassembly_position_at(self.pos, self.disassemblySettings), self.disassemblySettings):
      if line.contents.address == self.pos:
        break
      else:
        disassBlockOffset += 1

    # Displacement in lines between the top of the screen and the current disassembly block's top
    realOffset = self.posOffset - disassBlockOffset
    self.realOffset = realOffset
    # Generate two cursors, one for loading up one for loading down
    curPosU = self.bv.get_linear_disassembly_position_at(self.pos, self.disassemblySettings)  # Get linear disassembly position
    topLines = []
    while len(topLines) < realOffset:
      newLines = self.bv.get_previous_linear_disassembly_lines(curPosU, self.disassemblySettings)
      if len(newLines) == 0:
        break
      else:
        topLines = newLines + topLines

    curPosD = self.bv.get_linear_disassembly_position_at(self.pos, self.disassemblySettings)  # Get linear disassembly position
    bottomLines = []
    while len(bottomLines) <= (self.linearDisassemblyScreen.getmaxyx()[0]-2) - realOffset:
      newLines = self.bv.get_next_linear_disassembly_lines(curPosD, self.disassemblySettings)
      if len(newLines) == 0:
        break
      else:
        bottomLines += newLines

    self.disassemblyLines = topLines + bottomLines
    if realOffset < 0:
      self.disassemblyLines = self.disassemblyLines[-1*realOffset:]
    else:
      self.disassemblyLines = self.disassemblyLines[len(topLines)-realOffset:]

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
      self.pos = selection.start
      self.cursorOffset = 0
      self.loadLinearDisassembly()

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

  def parseInput_xrefs(self, key):
    # TODO...impliment xrefs window up/down, cursor, and selection mechanics
    pass

  def parseInput_linear_main(self, key):
    # TODO...FIX...stop clipping

    # Scroll
    if key == self.program.settings["linearDisassemblyScrollDown"]:
      self.cursorOffset += 1
    elif key == self.program.settings["linearDisassemblyScrollUp"]:
     self.cursorOffset -= 1
    elif key == self.program.settings["linearDisassemblyPageDown"]:
      self.cursorOffset += self.linearDisassemblyScreen.getmaxyx()[0]-3
    elif key == self.program.settings["linearDisassemblyPageUp"]:
      self.cursorOffset -= self.linearDisassemblyScreen.getmaxyx()[0]-3

    # Adjust for off screen
    if self.cursorOffset < 0:
      self.posOffset -= self.cursorOffset
      self.cursorOffset = 0
      self.loadLinearDisassembly()
    elif self.cursorOffset > self.linearDisassemblyScreen.getmaxyx()[0]-3:
      self.posOffset -= self.cursorOffset - (self.linearDisassemblyScreen.getmaxyx()[0]-3)
      self.cursorOffset = self.linearDisassemblyScreen.getmaxyx()[0]-3
      self.loadLinearDisassembly()

    # Adjust for new address
    if self.disassemblyLines[self.cursorOffset].contents.address != self.pos:
      self.pos = self.disassemblyLines[self.cursorOffset].contents.address
      self.posOffset = self.cursorOffset  # TODO...FIX...will currently jump to the top of a block, also skips down in some cases?
      self.loadLinearDisassembly()

  def parseInput_linear(self, key):
    if self.program.settings["BinaryNinjaContextDualFocus"]:
      self.parseInput_functionList(key)
      self.parseInput_linear_main(key)
    elif self.focus == 0:
      self.parseInput_linear_main(key)
    elif self.focus == 1:
      self.parseInput_functionList(key)
    elif self.focus == 2:
      self.parseInput_xrefs(key)

  def parseInput_hex(self, key):
    lineLength = 24

    # Scroll
    if key == self.program.settings["hexViewRight"]:
      self.pos += 1
      if self.pos % lineLength == 0:
        self.hexOffset += 1
    elif key == self.program.settings["hexViewLeft"]:
      if self.pos % lineLength == 0:
        self.hexOffset -= 1
      self.pos -= 1
    elif key == self.program.settings["hexViewLineDown"]:
      self.hexOffset += 1
      self.pos += lineLength
    elif key == self.program.settings["hexViewLineUp"]:
      self.hexOffset -= 1
      self.pos -= lineLength
    elif key == self.program.settings["hexViewPageDown"]:
      self.hexOffset += self.hexScreen.getmaxyx()[0]-3
      self.pos += lineLength * (self.hexScreen.getmaxyx()[0]-3)
    elif key == self.program.settings["hexViewPageUp"]:
      self.hexOffset -= self.hexScreen.getmaxyx()[0]-3
      self.pos -= lineLength * (self.hexScreen.getmaxyx()[0]-3)

    # Adjust for off screen
    if self.hexOffset < 0:
      self.hexOffset = 0
    elif self.hexOffset > self.hexScreen.getmaxyx()[0]-3:
      self.hexOffset = self.hexScreen.getmaxyx()[0]-3

    if self.pos < self.bv.start:
      self.pos = self.bv.start
    elif self.pos > self.bv.end:
      self.pos = self.bv.end

    self.hexLines = []
    topOfScreen = (self.pos - (self.pos % lineLength)) - (self.hexOffset * lineLength)
    self.topOfScreen = topOfScreen
    self.br.seek(topOfScreen)
    # TODO...make this for loop at least reasonably efficient...it's seriously just a clusterfuck right now
    for _ in range(self.hexScreen.getmaxyx()[0]-2):
      offset = "{:08x}   ".format(self.br.offset)
      byteValues = ''.join(["{:02x} ".format(b) for b in self.br.read(lineLength)])[:-1]
      asciiValues = ''.join([chr(int(b, 16)) if (int(b, 16) > 31 and int(b, 16) < 127) else '.' for b in byteValues.split(' ')])
      self.hexLines.append(offset + byteValues + "   " + asciiValues)

  def parseInput_cfg_main(self, key):
    pass  # TODO...impliment parseInput_cfg_main

  def parseInput_cfg(self, key):
    if self.program.settings["BinaryNinjaContextDualFocus"]:
      self.parseInput_cfg_main(key)
      self.parseInput_functionList(key)
    elif self.focus == 0:
      self.parseInput_cfg_main(key)
    elif self.focus == 1:
      self.parseInput_functionList(key)
    elif self.focus == 2:
      self.parseInput_xrefs(key)

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
        self.loadLinearDisassembly()
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
    # TODO Fix the lag induced by fetching the names of the functions (seems to take forever)
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

    # TODO...get and render xrefs in a more elegant manner

    xrefs = self.bv.get_code_refs(self.pos)
    xrefLines = []
    for yLine, xref in zip(range(len(xrefs)), xrefs):
      line = "{:08x}".format(xref.address)
      line += " in " + xref.function.name
      xrefLines.append(line)
      line = "   " + self.bv.get_disassembly(xref.address)
      xrefLines.append(line)
    drawList(1, 2, xrefLines, self.xrefsScreen, boarder=True)

    if len(xrefLines) == 0:
      self.xrefsScreen.addstr(1, 2, ":(")

    self.xrefsScreen.noutrefresh(0, 0, curses.LINES-1-self.program.settings["xrefsScreenHeight"], 0, curses.LINES-2, self.program.settings["functionListScreenWidth"])

  def render_linear(self):
    self.render_functionList()
    self.render_xrefs()

    self.linearDisassemblyScreen.erase()
    if self.focus == 0 and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.linearDisassemblyScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.linearDisassemblyScreen.border()

    rendRange = 0
    if len(self.disassemblyLines) < self.linearDisassemblyScreen.getmaxyx()[0]-2:
      rendRange = range(len(self.disassemblyLines))
    else:
      rendRange = range(self.linearDisassemblyScreen.getmaxyx()[0]-2)

    for yLine, textLine in zip(rendRange, self.disassemblyLines):
      if yLine == self.cursorOffset:
        # TODO Turn into line highlight instead, sift text back over to the left
        self.linearDisassemblyScreen.addstr(yLine+1, 1, '>' + str(textLine))
      else:
        self.linearDisassemblyScreen.addstr(yLine+1, 2, str(textLine))

    self.linearDisassemblyScreen.noutrefresh(0, 0, 0, self.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

  def render_hex(self):
    self.hexScreen.erase()
    self.hexScreen.border()

    # TODO...impliment cursor highlight

    for yLine, rawBytes in zip(range(len(self.hexLines)), self.hexLines):
      if yLine == self.hexOffset:
        self.hexScreen.addstr(yLine+1, 1, ">" + rawBytes)
      else:
        self.hexScreen.addstr(yLine+1, 2, rawBytes)

    self.hexScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2, curses.COLS-1)

  def render_cfg(self):
    self.render_functionList()
    self.render_xrefs()

    self.cfgScreen.erase()
    if self.focus == 0 and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.cfgScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.cfgScreen.border()

    # TODO...impliment render_cfg (still need to render actual graphs..)
    drawMultiLineText(1, 1, "Control Flow Graph!", self.cfgScreen)
    self.cfgScreen.noutrefresh(0, 0, 0, self.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

  def render_alerts(self):
    self.alertsScreen.erase()

    alerts = ""
    alerts += str(self.bv) + "   "
    alerts += "Cursor Position: " + hex(self.pos) + "   "
    try:
      alerts += "Disass Lines: " + str(len(self.disassemblyLines)) + "   "
      alerts += "PosOffset: " + str(self.posOffset) + "   "
      alerts += "LinDisCursOffset: " + str(self.cursorOffset) + "   "
      alerts += "realOff: " + str(self.realOffset) + "   "
      # alerts +=  + "   "
    except:
      pass
    self.alertsScreen.addstr(0, 0, alerts)
    self.alertsScreen.noutrefresh(0, 0, curses.LINES-1, 0, curses.LINES-1, curses.COLS-1)

  def render(self):
    if self.view == 0:
      self.render_linear()
    elif self.view == 1:
      self.render_hex()
    elif self.view == 2:
      self.render_cfg()

    self.render_alerts()
