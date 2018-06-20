from components.BinaryNinjaContext import *
from components.MainMenuContext import *
from components.SettingsModule import *
import curses


class ProgramState():
  """ A class to hold atributes about the running program """

  def __init__(self, screen, bv=None):
    # Curses Settings
    curses.curs_set(False)
    screen.nodelay(True)

    self.screen = screen
    self.is_running = True
    self.settings = SettingsModule()

    if bv is None:
      self.context = MainMenuContext(self, screen)
    else:
      self.context = BinaryNinjaContext(self, screen, bv)

  def __del__(self):
    curses.curs_set(True)

  def parseInput(self, key):
    # Manage Global KeyBindings First
    if key == self.settings["Key_Shutdown"]:
      self.shutdown()

    # Secondly Manage Context-Specific Keybindings
    self.context.parseInput(key)

  def render(self):
    self.context.render()

  def shutdown(self):
    self.is_running = False
