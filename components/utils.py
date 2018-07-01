# Give it a string and it will seperate at newlines
def drawMultiLineText(y, x, string, screen):
  for yLine,line in zip(range(y, y+len(string.split('\n'))), string.split('\n')):
    screen.addstr(yLine, x, line)


# Each element of the list goes on a new line
def drawMultiLineList(y, x, stringList, screen):
  for yLine,line in zip(range(y, y+len(stringList)), stringList):
    screen.addstr(yLine, x, line)


# Each element of the list goes on a new line, clips long lines, stops at the end
def drawList(y, x, stringList, screen, maxWidth=None, maxHeight=None, boarder=False):
  if boarder:
    if maxWidth is None:
      maxWidth = screen.getmaxyx()[1]-1-x
    if maxHeight is None:
      maxHeight = screen.getmaxyx()[0]-1
  else:
    if maxWidth is None:
      maxWidth = screen.getmaxyx()[1]-x
    if maxHeight is None:
      maxHeight = screen.getmaxyx()[0]

  for yLine,line in zip(range(y, maxHeight), stringList):
    screen.addstr(yLine, x, line[:maxWidth])
