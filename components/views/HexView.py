from components.utils import drawMultiLineText
from binaryninja import BinaryReader
import curses


class HexView():

  def __init__(self, bnc):
    self.bnc = bnc

    self.br = BinaryReader(bnc.bv)

    self.hexScreen = curses.newpad(curses.LINES-1, curses.COLS)
    self.hexOffset = 0
    self.hexCursor = bnc.pos
    self.loadHexLines()

  def loadHexLines(self):
    # Get lines to render
    self.hexLines = []
    topOfScreen = (self.bnc.pos- (self.bnc.pos% self.bnc.program.settings["hexLineLength"])) - (self.hexOffset * self.bnc.program.settings["hexLineLength"])
    self.topOfScreen = topOfScreen
    self.br.seek(topOfScreen)
    # TODO...make this for loop at least reasonably efficient...it's seriously just a clusterfuck right now
    for _ in range(self.hexScreen.getmaxyx()[0]-2):
      offset = "{:08x}   ".format(self.br.offset)
      line_bytes = self.br.read(self.bnc.program.settings["hexLineLength"])
      
      # Sections that don't exist in the memory
      if line_bytes is None:
        line_bytes = b''
        line_byte = self.br.read(1)
        while line_byte is not None:
          line_bytes += line_byte
          line_byte = self.br.read(1)

      if len(line_bytes) == self.bnc.program.settings["hexLineLength"]:
        byteValues = ''.join(["{:02x} ".format(b) for b in line_bytes])[:-1]
        asciiValues = ''.join([chr(int(b, 16)) if (int(b, 16) > 31 and int(b, 16) < 127) else '.' for b in byteValues.split(' ')])
        self.hexLines.append(offset + byteValues + "   " + asciiValues)

      else:
        byteValues = ''.join(["{:02x} ".format(b) for b in line_bytes])[:-1]
        asciiValues = ''.join([chr(int(b, 16)) if (int(b, 16) > 31 and int(b, 16) < 127) else '.' for b in byteValues.split(' ')[:-1]])
        self.hexLines.append(offset + byteValues + " "*(self.bnc.program.settings["hexLineLength"]*3-len(byteValues)) + "  " + asciiValues)
        if (len(self.hexLines) != self.hexScreen.getmaxyx()[0]-2):
          self.hexLines.append('-'*(self.bnc.program.settings["hexLineLength"]*4 + 13))

        line_byte = None
        while line_byte is None and self.br.offset <= self.bnc.bv.end:
          self.br.seek(self.br.offset+1)
          line_byte = self.br.read(1)
        self.br.seek(self.br.offset-1)

      if (len(self.hexLines) == self.hexScreen.getmaxyx()[0]-2):
        break

  def parseInput(self, key):
    # Scroll
    if key == self.bnc.program.settings["hexViewRight"]:
      self.hexCursor += 0.5

      if self.hexCursor%1.0 == 0:
        self.bnc.pos+= 1
        if self.bnc.pos% self.bnc.program.settings["hexLineLength"] == 0:
          self.hexOffset += 1

    elif key == self.bnc.program.settings["hexViewLeft"]:
      self.hexCursor -= 0.5

      if self.hexCursor%1.0 == 0.5:
        if self.bnc.pos% self.bnc.program.settings["hexLineLength"] == 0:
          self.hexOffset -= 1
        self.bnc.pos-= 1

    elif key == self.bnc.program.settings["hexViewLineDown"]:
      self.hexOffset += 1
      self.bnc.pos+= self.bnc.program.settings["hexLineLength"]
      self.hexCursor += self.bnc.program.settings["hexLineLength"]
    elif key == self.bnc.program.settings["hexViewLineUp"]:
      self.hexOffset -= 1
      self.bnc.pos-= self.bnc.program.settings["hexLineLength"]
      self.hexCursor -= self.bnc.program.settings["hexLineLength"]
    elif key == self.bnc.program.settings["hexViewPageDown"]:
      self.hexOffset += self.hexScreen.getmaxyx()[0]-3
      self.bnc.pos+= self.bnc.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
      self.hexCursor += self.bnc.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
    elif key == self.bnc.program.settings["hexViewPageUp"]:
      self.hexOffset -= self.hexScreen.getmaxyx()[0]-3
      self.bnc.pos-= self.bnc.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
      self.hexCursor -= self.bnc.program.settings["hexLineLength"] * (self.hexScreen.getmaxyx()[0]-3)
    
    elif key in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
      if self.hexCursor % 1.0 == 0.5:
        self.bnc.bv.write(self.bnc.pos, (int(key, 16) |
          (ord(self.bnc.bv.read(self.bnc.pos, 1).decode('charmap')) & 0b11110000)).to_bytes(1, 'big'))

        self.hexCursor += 0.5
        self.bnc.pos+= 1
        if self.bnc.pos% self.bnc.program.settings["hexLineLength"] == 0:
          self.hexOffset += 1
      else:
        self.bnc.bv.write(self.bnc.pos, (int(key, 16) << 4 |
          (ord(self.bnc.bv.read(self.bnc.pos, 1).decode('charmap')) & 0b00001111)).to_bytes(1, 'big'))

        self.hexCursor += 0.5

    # Adjust for off screen
    if self.hexOffset < 0:
      self.hexOffset = 0
    elif self.hexOffset > self.hexScreen.getmaxyx()[0]-3:
      self.hexOffset = self.hexScreen.getmaxyx()[0]-3

    if self.bnc.pos< self.bnc.bv.start:
      self.bnc.pos= self.bnc.bv.start
      self.hexCursor = self.bnc.pos
    elif self.bnc.pos> self.bnc.bv.end:
      self.bnc.pos= self.bnc.bv.end
      self.hexCursor = self.bnc.pos+ 0.5

    #   if self.hexOffset == skippedLinesLine:
    # if key == self.bnc.program.settings["hexViewLineUp"] or key == self.bnc.program.settings["hexViewPageUp"]:
    #   self.hexOffset -= 1
    # if key == self.bnc.program.settings["hexViewLineDown"] or key == self.bnc.program.settings["hexViewPageDown"]:
    #   self.hexOffset += 1
    #   self.bnc.pos= self.br.offset

    self.loadHexLines()

  def render(self):
    self.hexScreen.erase()
    self.hexScreen.border()

    for yLine, rawBytes in enumerate(self.hexLines):
      if yLine == self.hexOffset:
        for xLine, rawByte in enumerate(rawBytes):
          if self.hexCursor%self.bnc.program.settings["hexLineLength"] == (xLine-8-3)//3 + ((xLine-8-3)%3)/2.0 and (xLine-8-3)%3 != 2:
            self.hexScreen.addstr(yLine+1, 2+xLine, rawByte, curses.A_STANDOUT)
          else:
            self.hexScreen.addstr(yLine+1, 2+xLine, rawByte)
      else:
        self.hexScreen.addstr(yLine+1, 2, rawBytes)

    title = "Hex"
    drawMultiLineText(0, self.hexScreen.getmaxyx()[1]-len(title)-3, title, self.hexScreen)
    self.hexScreen.noutrefresh(0, 0, 0, 0, curses.LINES-2, curses.COLS-1)
