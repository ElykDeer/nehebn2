import json


class SettingsModule():
  """ A class to serve as a buffer for user settings """
  def __init__(self):
    self.filename = "settings.json"
    self.dirty = False  # 'Changed value' flag
    self.load()

  def __getitem__(self, key):
    """ Fetch a setting """
    return self.settingsObject[key]

  def __setitem__(self, key, value):
    """ Add new options or update old ones """
    self.dirty = True
    self.settingsObject[key] = value

  def __del__(self):
    """ Upon destruction of this object, save its data """
    if self.dirty:
      self.save()

  def load(self):
    """ Load settings from a file """
    with open(self.filename) as settingsFile:
      self.settingsObject = json.load(settingsFile)

  def save(self):
    """ Save the settings object to a file """
    with open(self.filename, 'w') as settingsFile:
      json.dump(self.settingsObject, settingsFile)
