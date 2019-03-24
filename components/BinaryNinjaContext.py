from components.utils import drawMultiLineText
from binaryninja import DisassemblySettings
# from .views import LinearView.LinearView, HexView.HexView, CFGView.CFGView
from .views.LinearView import LinearView
from .views.HexView    import HexView
from .views.CFGView    import CFGView
from enum import Enum
import curses


# TODO...Loosely ordered by importance:
# TODO...implement color themes with the new color theme format courtesy of peter
# TODO...implement disassembly options
# TODO...implement scroll bars on windows?, and the setting to disable them
# TODO...implement patching linear/cfg
# TODO...implement the ability to cursor into linear assembly lines.
# TODO...implement undo!  I think the API actually takes care of this for us nicely, but editing has to be implemented first and it'd be nice to snap the view back to whatever is being edited too


class BinaryNinjaContext():
  """ The BinaryNinja UI """

  class View(Enum):
    LINEAR = 0
    HEX    = 1
    CFG    = 2

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
    self.disassemblySettings = DisassemblySettings()
    
    self.pos = self.bv.start     # Current position in the binary

    # Global Stuff
    self.view  = BinaryNinjaContext.View.LINEAR
    self.popup = BinaryNinjaContext.Popup.NONE

    # Set up first view
    self.currentView = LinearView(self)

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
      del self.currentView

      # Switch Contexts
      if self.view == BinaryNinjaContext.View.LINEAR:
        self.view = BinaryNinjaContext.View.HEX
      elif self.view == BinaryNinjaContext.View.HEX:
        self.view = BinaryNinjaContext.View.CFG
      elif self.view == BinaryNinjaContext.View.CFG:
        self.view = BinaryNinjaContext.View.LINEAR

      # Setup
      if self.view == BinaryNinjaContext.View.LINEAR:
        self.currentView = LinearView(self)
      elif self.view == BinaryNinjaContext.View.HEX:
        self.currentView = HexView(self)
      elif self.view == BinaryNinjaContext.View.CFG:
        self.currentView = CFGView(self)

    # Popup context switches
    elif (key == self.program.settings["popupWindowGoto"].lower() or key == self.program.settings["popupWindowGoto"].upper()) and self.popup == BinaryNinjaContext.Popup.NONE:
      self.popup = BinaryNinjaContext.Popup.GOTO
      self.gotoInput = ['_'] * 12
      self.gotoCursor = 0

    # Popup input capturing
    elif self.popup == BinaryNinjaContext.Popup.GOTO:
      self.parseInput_popup_goto(key)
    
    # Views input capturing
    self.currentView.parseInput(key)

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
    self.currentView.render()
    self.render_alerts()
    self.render_popups()
