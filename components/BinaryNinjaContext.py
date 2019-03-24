from components.utils import drawList, drawMultiLineText
import binaryninja as binja
from enum import Enum
import curses


# TODO...Loosely ordered by importance:
# TODO...maybe seperate each view into a class to make cleaning up the various view-dependant variables neater?
# TODO...implement color themes with the new color theme format courtesy of peter
# TODO...implement disassembly options
# TODO...implement scroll bars on windows?, and the setting to disable them
# TODO...implement the ability to edit what we're seeing.. Enter an insert mode in Hex view (or be in it by defualt like in BN proper), and have patches availible in linear/cfg
# TODO...implement the ability to cursor into linear assembly lines.
# TODO...implement undo!  I think the API actually takes care of this for us nicely, but editing has to be implemented first and it'd be nice to snap the view back to whatever is being edited too


class BinaryNinjaContext():
  """ The BinaryNinja UI """

  class View(Enum):
    LINEAR = 0
    HEX    = 1
    CFG    = 2

  class Focus(Enum):
    MAIN = 0
    FUNC = 1
    XREF = 2

  class Popup(Enum):
    NONE = 0
    GOTO = 1

  def __init__(self, program, screen, bv):
    self.program = program
    self.screen = screen
    self.bv = bv

    # Make Pads
    self.alertsScreen = curses.newpad(1, curses.COLS)
    self.pythonConsoleScreen = curses.newpad(1, curses.COLS)
    self.logScreen = curses.newpad(1, curses.COLS)
    self.popupGotoScreen = curses.newpad(3, 16)

    # Disassembly Window Stuff
    self.disassemblySettings = binja.DisassemblySettings()
    
    self.pos = self.bv.start     # Current position in the binary
    self.posOffset = 0           # Displacement in lines between the top of the screen and the rendered location of self.pos
    self.cursorOffset = 0        # Offset (in lines) from the top of the screen to the current visual cursor in linear view
    self.disassemblyLines = []

    self.br = binja.BinaryReader(bv)

    # Function List Pane Stuff
    self.funcListPos = 0
    self.funcListCur = 0
    self.updateFunctionList = True

    # Global Stuff
    self.focus = BinaryNinjaContext.Focus.MAIN
    self.view  = BinaryNinjaContext.View.LINEAR
    self.popup = BinaryNinjaContext.Popup.NONE

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

  def loadHexLines(self):
    # Get lines to render
    self.hexLines = []
    topOfScreen = (self.pos - (self.pos % self.program.settings["hexLineLength"])) - (self.hexOffset * self.program.settings["hexLineLength"])
    self.topOfScreen = topOfScreen
    self.br.seek(topOfScreen)
    # TODO...make this for loop at least reasonably efficient...it's seriously just a clusterfuck right now
    for _ in range(self.hexScreen.getmaxyx()[0]-2):
      offset = "{:08x}   ".format(self.br.offset)
      line_bytes = self.br.read(self.program.settings["hexLineLength"])
      
      # Sections that don't exist in the memory
      if line_bytes is None:
        line_bytes = b''
        line_byte = self.br.read(1)
        while line_byte is not None:
          line_bytes += line_byte
          line_byte = self.br.read(1)

      if len(line_bytes) == self.program.settings["hexLineLength"]:
        byteValues = ''.join(["{:02x} ".format(b) for b in line_bytes])[:-1]
        asciiValues = ''.join([chr(int(b, 16)) if (int(b, 16) > 31 and int(b, 16) < 127) else '.' for b in byteValues.split(' ')])
        self.hexLines.append(offset + byteValues + "   " + asciiValues)

      else:
        byteValues = ''.join(["{:02x} ".format(b) for b in line_bytes])[:-1]
        asciiValues = ''.join([chr(int(b, 16)) if (int(b, 16) > 31 and int(b, 16) < 127) else '.' for b in byteValues.split(' ')[:-1]])
        self.hexLines.append(offset + byteValues + " "*(self.program.settings["hexLineLength"]*3-len(byteValues)) + "  " + asciiValues)
        if (len(self.hexLines) != self.hexScreen.getmaxyx()[0]-2):
          self.hexLines.append('-'*(self.program.settings["hexLineLength"]*4 + 13))

        line_byte = None
        while line_byte is None and self.br.offset <= self.bv.end:
          self.br.seek(self.br.offset+1)
          line_byte = self.br.read(1)
        self.br.seek(self.br.offset-1)

      if (len(self.hexLines) == self.hexScreen.getmaxyx()[0]-2):
        break

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

    # TODO...Implement Wrap Around
    # TODO...Implement Not Crashing On Moving Past Buffer

    self.updateFunctionList = True

  def parseInput_xrefs(self, key):
    # TODO...implement xrefs window up/down, cursor, and selection mechanics
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
    elif self.focus == BinaryNinjaContext.Focus.MAIN:
      self.parseInput_linear_main(key)
    elif self.focus == BinaryNinjaContext.Focus.FUNC:
      self.parseInput_functionList(key)
    elif self.focus == BinaryNinjaContext.Focus.XREF:
      self.parseInput_xrefs(key)

  def parseInput_hex(self, key):
    # Scroll
    if key == self.program.settings["hexViewRight"]:
      self.hexCursor += 0.5

      if self.hexCursor%1.0 == 0:
        self.pos += 1
        if self.pos % self.program.settings["hexLineLength"] == 0:
          self.hexOffset += 1

    elif key == self.program.settings["hexViewLeft"]:
      self.hexCursor -= 0.5

      if self.hexCursor%1.0 == 0.5:
        if self.pos % self.program.settings["hexLineLength"] == 0:
          self.hexOffset -= 1
        self.pos -= 1

    elif key == self.program.settings["hexViewLineDown"]:
      self.hexOffset += 1
      self.pos += self.program.settings["hexLineLength"]
      self.hexCursor += self.program.settings["hexLineLength"]
    elif key == self.program.settings["hexViewLineUp"]:
      self.hexOffset -= 1
      self.pos -= self.program.settings["hexLineLength"]
      self.hexCursor -= self.program.settings["hexLineLength"]
    elif key == self.program.settings["hexViewPageDown"]:
      self.hexOffset += self.hexScreen.getmaxyx()[0]-3
      self.pos += self.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
      self.hexCursor += self.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
    elif key == self.program.settings["hexViewPageUp"]:
      self.hexOffset -= self.hexScreen.getmaxyx()[0]-3
      self.pos -= self.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
      self.hexCursor -= self.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
    
    elif key in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
      if self.hexCursor % 1.0 == 0.5:
        self.bv.write(self.pos, (int(key, 16) |
          (ord(self.bv.read(self.pos, 1).decode('charmap')) & 0b11110000)).to_bytes(1, 'big'))

        self.hexCursor += 0.5
        self.pos += 1
        if self.pos % self.program.settings["hexLineLength"] == 0:
          self.hexOffset += 1
      else:
        self.bv.write(self.pos, (int(key, 16) << 4 |
          (ord(self.bv.read(self.pos, 1).decode('charmap')) & 0b00001111)).to_bytes(1, 'big'))

        self.hexCursor += 0.5

    # Adjust for off screen
    if self.hexOffset < 0:
      self.hexOffset = 0
    elif self.hexOffset > self.hexScreen.getmaxyx()[0]-3:
      self.hexOffset = self.hexScreen.getmaxyx()[0]-3

    if self.pos < self.bv.start:
      self.pos = self.bv.start
      self.hexCursor = self.pos
    elif self.pos > self.bv.end:
      self.pos = self.bv.end
      self.hexCursor = self.pos + 0.5

    #   if self.hexOffset == skippedLinesLine:
    # if key == self.program.settings["hexViewLineUp"] or key == self.program.settings["hexViewPageUp"]:
    #   self.hexOffset -= 1
    # if key == self.program.settings["hexViewLineDown"] or key == self.program.settings["hexViewPageDown"]:
    #   self.hexOffset += 1
    #   self.pos = self.br.offset

    self.loadHexLines()

  def parseInput_cfg_main(self, key):
    pass  # TODO...implement parseInput_cfg_main

  def parseInput_cfg(self, key):
    if self.program.settings["BinaryNinjaContextDualFocus"]:
      self.parseInput_cfg_main(key)
      self.parseInput_functionList(key)
    elif self.focus == BinaryNinjaContext.Focus.MAIN:
      self.parseInput_cfg_main(key)
    elif self.focus == BinaryNinjaContext.Focus.FUNC:
      self.parseInput_functionList(key)
    elif self.focus == BinaryNinjaContext.Focus.XREF:
      self.parseInput_xrefs(key)

  def parseInput_popup_goto(self, key):
    if key == "KEY_BACKSPACE":
      if self.gotoCursor > 0:
        self.gotoCursor -= 1
        self.gotoInput[self.gotoCursor] = "_"
      else:
        self.popup = BinaryNinjaContext.Popup.NONE
        del self.gotoInput
        del self.gotoCursor

    elif key == self.program.settings["confirm"]:
      try:
        gotoInput = eval(''.join(self.gotoInput[:self.gotoCursor]))
        if isinstance(gotoInput, int):

          if self.view == BinaryNinjaContext.View.LINEAR:
            self.pos = gotoInput
            self.cursorOffset = 0
            self.loadLinearDisassembly()
          elif self.view == BinaryNinjaContext.View.HEX:
            self.pos = gotoInput
            self.loadHexLines()
          elif self.view == BinaryNinjaContext.View.CFG:
            self.pos = gotoInput

          self.popup = BinaryNinjaContext.Popup.NONE
          del self.gotoInput
          del self.gotoCursor
      except:
        pass


    elif key == "KEY_LEFT":
      if self.gotoCursor > 0:
        self.gotoCursor -= 1
    elif key == "KEY_RIGHT":
      if self.gotoCursor < len(self.gotoInput):
        self.gotoCursor -= 1

    elif not key == '':  # `User is Typing...``
      if self.gotoCursor < len(self.gotoInput):
        self.gotoInput[self.gotoCursor] = key
        self.gotoCursor += 1
        # Clear the rest of the string
        for i in range(self.gotoCursor, len(self.gotoInput)):
          self.gotoInput[i] = '_'

  def parseInput(self, key):
    if key == self.program.settings["BinaryNinjaContextSwitchView"]:
      # Clean Up
      if self.view == BinaryNinjaContext.View.LINEAR:
        del self.linearDisassemblyScreen
        del self.functionListScreen
        del self.xrefsScreen
      elif self.view == BinaryNinjaContext.View.HEX:
        del self.hexScreen
        del self.hexCursor
        del self.hexLines
        del self.hexOffset
      elif self.view == BinaryNinjaContext.View.CFG:
        del self.cfgScreen
        del self.functionListScreen
        del self.xrefsScreen

      # Switch Contexts
      if self.view == BinaryNinjaContext.View.LINEAR:
        self.view = BinaryNinjaContext.View.HEX
      elif self.view == BinaryNinjaContext.View.HEX:
        self.view = BinaryNinjaContext.View.CFG
      elif self.view == BinaryNinjaContext.View.CFG:
        self.view = BinaryNinjaContext.View.LINEAR

      # Setup
      if self.view == BinaryNinjaContext.View.LINEAR:
        self.updateFunctionList = True
        self.linearDisassemblyScreen = curses.newpad(curses.LINES-1, curses.COLS - self.program.settings["functionListScreenWidth"])
        self.functionListScreen = curses.newpad(curses.LINES-1-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
        self.xrefsScreen = curses.newpad(self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
        self.loadLinearDisassembly()
      elif self.view == BinaryNinjaContext.View.HEX:
        self.updateFunctionList = True
        self.hexScreen = curses.newpad(curses.LINES-1, curses.COLS)
        self.hexOffset = 0
        self.hexCursor = self.pos
        self.loadHexLines()
      elif self.view == BinaryNinjaContext.View.CFG:
        self.cfgScreen = curses.newpad(curses.LINES-1, curses.COLS - self.program.settings["functionListScreenWidth"])
        self.functionListScreen = curses.newpad(curses.LINES-1-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])
        self.xrefsScreen = curses.newpad(self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])

    elif key == self.program.settings["BinaryNinjaContextSwitchFocus"]:
      if self.focus == BinaryNinjaContext.Focus.MAIN:
        self.focus = BinaryNinjaContext.Focus.FUNC
      elif self.focus == BinaryNinjaContext.Focus.FUNC:
        self.focus = BinaryNinjaContext.Focus.XREF
      elif self.focus == BinaryNinjaContext.Focus.XREF:
        self.focus = BinaryNinjaContext.Focus.MAIN

    # Popup context switches
    elif (key == self.program.settings["popupWindowGoto"].lower() or key == self.program.settings["popupWindowGoto"].upper()) and self.popup == BinaryNinjaContext.Popup.NONE:
      self.popup = BinaryNinjaContext.Popup.GOTO
      self.gotoInput = ['_'] * 12
      self.gotoCursor = 0

    # Popup input capturing
    elif self.popup == BinaryNinjaContext.Popup.GOTO:
      self.parseInput_popup_goto(key)
    
    # Views input capturing
    elif self.view == BinaryNinjaContext.View.LINEAR:
      self.parseInput_linear(key)
    elif self.view == BinaryNinjaContext.View.HEX:
      self.parseInput_hex(key)
    elif self.view == BinaryNinjaContext.View.CFG:
      self.parseInput_cfg(key)

  def render_functionList(self):
    # Not the best implementation of this...but it makes only the functionList window input-lag (unless in dual focus mode... :/ )
    # TODO...FIX the lag induced by fetching the names of the functions (seems to take forever)
    if self.updateFunctionList:
      self.functionListScreen.erase()

    if self.focus == BinaryNinjaContext.Focus.FUNC and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.functionListScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.functionListScreen.border()

    if self.updateFunctionList:
      for yLine in range(self.funcListPos, self.funcListPos+(curses.LINES-3)-self.program.settings["xrefsScreenHeight"]):
        if yLine == self.funcListCur + self.funcListPos:
          self.functionListScreen.addstr(yLine-self.funcListPos+1, 3, self.bv.functions[yLine].name, curses.A_STANDOUT)  # Name access is slow
        else:
          self.functionListScreen.addstr(yLine-self.funcListPos+1, 3, self.bv.functions[yLine].name)  # Name access is slow
      self.updateFunctionList = False

    title = "Function List"
    drawMultiLineText(0, self.program.settings["functionListScreenWidth"]-len(title)-2, title, self.functionListScreen)
    self.functionListScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2-self.program.settings["xrefsScreenHeight"], self.program.settings["functionListScreenWidth"])

  def render_xrefs(self):
    self.xrefsScreen.erase()
    if self.focus == BinaryNinjaContext.Focus.XREF and not self.program.settings["BinaryNinjaContextDualFocus"]:
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

    title = "XREFS"
    drawMultiLineText(0, self.program.settings["functionListScreenWidth"]-len(title)-2, title, self.xrefsScreen)
    self.xrefsScreen.noutrefresh(0, 0, curses.LINES-1-self.program.settings["xrefsScreenHeight"], 0, curses.LINES-2, self.program.settings["functionListScreenWidth"])

  def render_linear(self):
    self.render_functionList()
    self.render_xrefs()

    self.linearDisassemblyScreen.erase()
    if self.focus == BinaryNinjaContext.Focus.MAIN and not self.program.settings["BinaryNinjaContextDualFocus"]:
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
        self.linearDisassemblyScreen.addstr(yLine+1, 2, str(textLine), curses.A_STANDOUT)
      else:
        self.linearDisassemblyScreen.addstr(yLine+1, 2, str(textLine))

    title = "Linear"
    drawMultiLineText(0, self.linearDisassemblyScreen.getmaxyx()[1]-len(title)-3, title, self.linearDisassemblyScreen)
    self.linearDisassemblyScreen.noutrefresh(0, 0, 0, self.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

  def render_hex(self):
    self.hexScreen.erase()
    self.hexScreen.border()

    for yLine, rawBytes in enumerate(self.hexLines):
      if yLine == self.hexOffset:
        for xLine, rawByte in enumerate(rawBytes):
          if self.hexCursor%self.program.settings["hexLineLength"] == (xLine-8-3)//3 + ((xLine-8-3)%3)/2.0 and (xLine-8-3)%3 != 2:
            self.hexScreen.addstr(yLine+1, 2+xLine, rawByte, curses.A_STANDOUT)
          else:
            self.hexScreen.addstr(yLine+1, 2+xLine, rawByte)
      else:
        self.hexScreen.addstr(yLine+1, 2, rawBytes)

    title = "Hex"
    drawMultiLineText(0, self.hexScreen.getmaxyx()[1]-len(title)-3, title, self.hexScreen)
    self.hexScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2, curses.COLS-1)

  def render_cfg(self):
    self.render_functionList()
    self.render_xrefs()

    self.cfgScreen.erase()
    if self.focus == BinaryNinjaContext.Focus.MAIN and not self.program.settings["BinaryNinjaContextDualFocus"]:
      self.cfgScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.cfgScreen.border()

    # TODO...implement render_cfg (still need to render actual graphs..)
    drawMultiLineText(1, 1, "Control Flow Graph!", self.cfgScreen)
    title = "CFG"
    drawMultiLineText(0, self.cfgScreen.getmaxyx()[1]-len(title)-3, title, self.cfgScreen)
    self.cfgScreen.noutrefresh(0, 0, 0, self.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

  def render_alerts(self):
    self.alertsScreen.erase()

    alerts = ""
    alerts += str(self.bv) + "   "
    alerts += "Cursor Position: " + hex(self.pos) + "   "
    try:
      # alerts += "Disass Lines: " + str(len(self.disassemblyLines)) + "   "
      alerts += "PosOffset: " + str(self.posOffset) + "   "
      # alerts += "LinDisCursOffset: " + str(self.cursorOffset) + "   "
      # alerts += "realOff: " + str(self.realOffset) + "   "
      alerts += "hexCursor: " + str(self.hexCursor) + "   "
      alerts += "xthing: " + str(self.xthing) + "   "
      # alerts += "" + str() + "   "
    except:
      pass
    self.alertsScreen.addstr(0, 0, alerts)
    self.alertsScreen.noutrefresh(0, 0, curses.LINES-1, 0, curses.LINES-1, curses.COLS-1)
  
  def render_popups(self):
    if self.popup == BinaryNinjaContext.Popup.NONE:
      return
    
    if self.popup == BinaryNinjaContext.Popup.GOTO:
      self.popupGotoScreen.erase()
      self.popupGotoScreen.border()

      drawMultiLineText(0, 10, "Goto", self.popupGotoScreen)
      drawMultiLineText(1, 2, ''.join(self.gotoInput), self.popupGotoScreen)
      self.popupGotoScreen.noutrefresh(0, 0, (curses.LINES//2)-1, (curses.COLS//2)-8, (curses.LINES//2)+2, (curses.COLS//2)+8)

  def render(self):
    if self.view == BinaryNinjaContext.View.LINEAR:
      self.render_linear()
    elif self.view == BinaryNinjaContext.View.HEX:
      self.render_hex()
    elif self.view == BinaryNinjaContext.View.CFG:
      self.render_cfg()

    self.render_alerts()
    self.render_popups()
