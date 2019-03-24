from components.utils import drawMultiLineText
from .LeftSideBar import LeftSideBar
from enum import Enum
import curses


class LinearView():
  class Focus(Enum):
    MAIN = 0
    FUNC = 1
    XREF = 2

  def __init__(self, bnc):
    self.bnc = bnc

    self.focus = LinearView.Focus.MAIN
    self.posOffset = 0           # Displacement in lines between the top of the screen and the rendered location of self.pos
    self.cursorOffset = 0        # Offset (in lines) from the top of the screen to the current visual cursor in linear view
    self.disassemblyLines = []

    self.leftSideBar = LeftSideBar(bnc)
    self.linearDisassemblyScreen = curses.newpad(curses.LINES-1, curses.COLS - self.bnc.program.settings["functionListScreenWidth"])
    self.loadLinearDisassembly()

  def loadLinearDisassembly(self):
    # Get current offset into block
    disassBlockOffset = 0
    for line in self.bnc.bv.get_next_linear_disassembly_lines(self.bnc.bv.get_linear_disassembly_position_at(self.bnc.pos, self.bnc.disassemblySettings), self.bnc.disassemblySettings):
      if line.contents.address == self.bnc.pos:
        break
      else:
        disassBlockOffset += 1

    # Displacement in lines between the top of the screen and the current disassembly block's top
    realOffset = self.posOffset - disassBlockOffset
    self.realOffset = realOffset
    # Generate two cursors, one for loading up one for loading down
    curPosU = self.bnc.bv.get_linear_disassembly_position_at(self.bnc.pos, self.bnc.disassemblySettings)  # Get linear disassembly position
    topLines = []
    while len(topLines) < realOffset:
      newLines = self.bnc.bv.get_previous_linear_disassembly_lines(curPosU, self.bnc.disassemblySettings)
      if len(newLines) == 0:
        break
      else:
        topLines = newLines + topLines

    curPosD = self.bnc.bv.get_linear_disassembly_position_at(self.bnc.pos, self.bnc.disassemblySettings)  # Get linear disassembly position
    bottomLines = []
    while len(bottomLines) <= (self.linearDisassemblyScreen.getmaxyx()[0]-2) - realOffset:
      newLines = self.bnc.bv.get_next_linear_disassembly_lines(curPosD, self.bnc.disassemblySettings)
      if len(newLines) == 0:
        break
      else:
        bottomLines += newLines

    self.disassemblyLines = topLines + bottomLines
    if realOffset < 0:
      self.disassemblyLines = self.disassemblyLines[-1*realOffset:]
    else:
      self.disassemblyLines = self.disassemblyLines[len(topLines)-realOffset:]

  def parseInput_main(self, key):
    # TODO...FIX...stop clipping

    # Scroll
    if key == self.bnc.program.settings["linearDisassemblyScrollDown"]:
      self.cursorOffset += 1
    elif key == self.bnc.program.settings["linearDisassemblyScrollUp"]:
     self.cursorOffset -= 1
    elif key == self.bnc.program.settings["linearDisassemblyPageDown"]:
      self.cursorOffset += self.linearDisassemblyScreen.getmaxyx()[0]-3
    elif key == self.bnc.program.settings["linearDisassemblyPageUp"]:
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
    if self.disassemblyLines[self.cursorOffset].contents.address != self.bnc.pos:
      self.bnc.pos = self.disassemblyLines[self.cursorOffset].contents.address
      self.posOffset = self.cursorOffset  # TODO...FIX...will currently jump to the top of a block, also skips down in some cases?
      self.loadLinearDisassembly()

  def parseInput(self, key):
    if key == self.bnc.program.settings["BinaryNinjaContextSwitchFocus"]:
      if self.focus == LinearView.Focus.MAIN:
        self.focus = LinearView.Focus.FUNC
      elif self.focus == LinearView.Focus.FUNC:
        self.focus = LinearView.Focus.XREF
      elif self.focus == LinearView.Focus.XREF:
        self.focus = LinearView.Focus.MAIN

    if self.bnc.program.settings["BinaryNinjaContextDualFocus"]:
      self.leftSideBar.parseInput_functionList(key)
      self.parseInput_main(key)
    elif self.focus == LinearView.Focus.MAIN:
      self.parseInput_main(key)
    elif self.focus == LinearView.Focus.FUNC:
      self.leftSideBar.parseInput_functionList(key)
    elif self.focus == LinearView.Focus.XREF:
      self.leftSideBar.parseInput_xrefs(key)

  def render(self):
    if self.focus == LinearView.Focus.FUNC:  
      self.leftSideBar.render(LeftSideBar.Focus.FUNC)
    elif self.focus == LinearView.Focus.XREF:  
      self.leftSideBar.render(LeftSideBar.Focus.XREF)
    else:
      self.leftSideBar.render(None)

    self.linearDisassemblyScreen.erase()
    if self.focus == LinearView.Focus.MAIN and not self.bnc.program.settings["BinaryNinjaContextDualFocus"]:
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
    self.linearDisassemblyScreen.noutrefresh(0, 0, 0, self.bnc.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)
