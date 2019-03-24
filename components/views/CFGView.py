from components.utils import drawMultiLineText
from .LeftSideBar import LeftSideBar
from enum import Enum
import curses


class CFGView():
  class Focus(Enum):
    MAIN = 0
    FUNC = 1
    XREF = 2

  def __init__(self, bnc):
    self.bnc = bnc

    self.focus = CFGView.Focus.MAIN

    self.leftSideBar = LeftSideBar(bnc)
    self.cfgScreen = curses.newpad(curses.LINES-1, curses.COLS - self.bnc.program.settings["functionListScreenWidth"])

  def parseInput_main(self, key):
    pass  # TODO...implement parseInput_main

  def parseInput(self, key):
    if key == self.bnc.program.settings["BinaryNinjaContextSwitchFocus"]:
      if self.focus == CFGView.Focus.MAIN:
        self.focus = CFGView.Focus.FUNC
      elif self.focus == CFGView.Focus.FUNC:
        self.focus = CFGView.Focus.XREF
      elif self.focus == CFGView.Focus.XREF:
        self.focus = CFGView.Focus.MAIN

    if self.bnc.program.settings["BinaryNinjaContextDualFocus"]:
      self.parseInput_main(key)
      self.leftSideBar.parseInput_functionList(key)
    elif self.focus == CFGView.Focus.MAIN:
      self.parseInput_main(key)
    elif self.focus == CFGView.Focus.FUNC:
      self.leftSideBar.parseInput_functionList(key)
    elif self.focus == CFGView.Focus.XREF:
      self.leftSideBar.parseInput_xrefs(key)

  def render(self):
    if self.focus == CFGView.Focus.FUNC:  
      self.leftSideBar.render(LeftSideBar.Focus.FUNC)
    elif self.focus == CFGView.Focus.XREF:  
      self.leftSideBar.render(LeftSideBar.Focus.XREF)
    else:
      self.leftSideBar.render(None)

    self.cfgScreen.erase()
    if self.focus == CFGView.Focus.MAIN and not self.bnc.program.settings["BinaryNinjaContextDualFocus"]:
      self.cfgScreen.border('#', '#', '#', '#', '#', '#', '#', '#')
    else:
      self.cfgScreen.border()

    # TODO...implement render_cfg (still need to render actual graphs..)
    drawMultiLineText(1, 1, "Control Flow Graph!", self.cfgScreen)
    title = "CFG"
    drawMultiLineText(0, self.cfgScreen.getmaxyx()[1]-len(title)-3, title, self.cfgScreen)
    self.cfgScreen.noutrefresh(0, 0, 0, self.bnc.program.settings["functionListScreenWidth"], curses.LINES-2, curses.COLS-1)

