def drawMultiLineText(y, x, string, screen):
  for yLine,line in zip(range(y, y+len(string.split('\n'))), string.split('\n')):
    screen.addstr(yLine, x, line)
