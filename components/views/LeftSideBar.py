from components.utils import drawList, drawMultiLineText
from enum import Enum
import curses


class LeftSideBar():
  class Focus(Enum):
    FUNC = 1
    XREF = 2
  
  def __init__(self, bnc):
    self.bnc = bnc

    self.functionListScreen = curses.newpad(curses.LINES-1-self.bnc.program.settings["xrefsScreenHeight"], self.bnc.program.settings["functionListScreenWidth"])
    self.xrefsScreen = curses.newpad(self.bnc.program.settings["xrefsScreenHeight"], self.bnc.program.settings["functionListScreenWidth"])

    # Function List Pane Stuff
    self.funcListPos = 0
    self.funcListCur = 0
    self.updateFunctionList = True

  def render_functionList(self, focus):
    # Not the best implementation of this...but it makes only the functionList window input-lag (unless in dual focus mode... :/ )
    # TODO...FIX the lag induced by fetching the names of the functions (seems to take forever)
    if self.updateFunctionList:
      self.functionListScreen.erase()

    if focus == LeftSideBar.Focus.FUNC and not self.bnc.program.settings["BinaryNinjaContextDualFocus"]:
      self.functionListScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.functionListScreen.border()

    if self.updateFunctionList:
      for yLine in range(self.funcListPos, self.funcListPos+(curses.LINES-3)-self.bnc.program.settings["xrefsScreenHeight"]):
        if yLine == self.funcListCur + self.funcListPos:
          self.functionListScreen.addstr(yLine-self.funcListPos+1, 3, self.bnc.bv.functions[yLine].name, curses.A_STANDOUT)  # Name access is slow
        else:
          self.functionListScreen.addstr(yLine-self.funcListPos+1, 3, self.bnc.bv.functions[yLine].name)  # Name access is slow
      self.updateFunctionList = False

    title = "Function List"
    drawMultiLineText(0, self.bnc.program.settings["functionListScreenWidth"]-len(title)-2, title, self.functionListScreen)
    self.functionListScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2-self.bnc.program.settings["xrefsScreenHeight"], self.bnc.program.settings["functionListScreenWidth"])

  def render_xrefs(self, focus):
    self.xrefsScreen.erase()
    if focus == LeftSideBar.Focus.XREF and not self.bnc.program.settings["BinaryNinjaContextDualFocus"]:
      self.xrefsScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.xrefsScreen.border()

    # TODO...get and render xrefs in a more elegant manner

    xrefs = self.bnc.bv.get_code_refs(self.bnc.pos)
    xrefLines = []
    for yLine, xref in zip(range(len(xrefs)), xrefs):
      line = "{:08x}".format(xref.address)
      line += " in " + xref.function.name
      xrefLines.append(line)
      line = "   " + self.bnc.bv.get_disassembly(xref.address)
      xrefLines.append(line)
    drawList(1, 2, xrefLines, self.xrefsScreen, boarder=True)

    if len(xrefLines) == 0:
      self.xrefsScreen.addstr(1, 2, ":(")

    title = "XREFS"
    drawMultiLineText(0, self.bnc.program.settings["functionListScreenWidth"]-len(title)-2, title, self.xrefsScreen)
    self.xrefsScreen.noutrefresh(0, 0, curses.LINES-1-self.bnc.program.settings["xrefsScreenHeight"], 0, curses.LINES-2, self.bnc.program.settings["functionListScreenWidth"])

  def render(self, focus):
    self.render_functionList(focus)
    self.render_xrefs(focus)

  def parseInput_functionList(self, key):
    bvFunctionsLen = len(self.bnc.bv.functions)
    if key == self.bnc.program.settings["functionListScrollDown"]:
      self.funcListCur += 1
    elif key == self.bnc.program.settings["functionListScrollUp"]:
      self.funcListCur -= 1
    elif key == self.bnc.program.settings["functionListPageDown"]:
      self.funcListCur += self.functionListScreen.getmaxyx()[0]-3
    elif key == self.bnc.program.settings["functionListPageUp"]:
      self.funcListCur -= self.functionListScreen.getmaxyx()[0]-3
    elif key == self.bnc.program.settings["functionListSelect"]:
      selection = self.bnc.bv.functions[self.funcListPos + self.funcListCur]
      self.bnc.pos= selection.start
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
