# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2012 ArxSys
# 
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
# 
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Johannes Binder <j.binder.x@gmail.com>

__dff_module_metahachoir_version__ = "1.0.0"

from api.module.script import Script 
from api.module.module import Module
from api.types.libtypes import Variant, VMap, Argument, typeId, vtime
from api.vfs.libvfs import AttributesHandler
from hachoir_core.error import HachoirError
from hachoir_metadata import extractMetadata
from hachoir_parser import guessParser
from hachoir_parser import QueryParser
from hachoir_core.stream.input import StringInputStream

class HachoirHandler(AttributesHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "hachoir")
    self.__disown__()

  def attributes(self, node):
    attr = VMap()
    attr.thisown = False
    file = node.open()
    parser = guessParser(StringInputStream(file.read()))
    file.close()
    if not parser:
      attr["info"] = "unable to read metadata"
      return attr

    try:
      metadata = extractMetadata(parser)
      for data in metadata:
        if not(any(data.values)):
          continue
        attr[data.key] = "; ".join([str(val.value) for val in data.values])
    except HachoirError, err:
      attr["info"] = "error while reading metadata"

    return attr

class MetaHachoir(Script):
  def __init__(self):
    Script.__init__(self, "metahachoir")
    self.handler = HachoirHandler()

  def start(self, args):
    try:
      node = args['file'].value()
      self.stateinfo = "Registering node: " + str(node.name())
      node.registerAttributes(self.handler)
    except KeyError:
      pass

  @staticmethod
  def getSupportedFileExtensions():
    extensions = list()
    for parser in QueryParser([]):
      file_ext = parser.getParserTags().get("file_ext")
      if not file_ext:
        continue
      extensions.extend(file_ext)
    return list(set(extensions) - set(['']))

class metahachoir(Module): 
  """This module shows metadata provided by Hachoir in node attributes"""
  def __init__(self):
    Module.__init__(self, "metahachoir", MetaHachoir)
    self.conf.addArgument({"name": "file",
                           "description": "file for extracting metadata",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "extension-type",
                           "type": typeId.String,
                           "description" : "compatible extensions",
                           "values" : MetaHachoir.getSupportedFileExtensions()})

    self.flags = ["single"]
    self.tags = "Metadata"
