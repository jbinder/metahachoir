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

class HachoirHandler(AttributesHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "hachoir")
    self.__disown__();

  def attributes(self, node):
    attr = VMap()
    attr.thisown = False
    file = node.open()
    attr["hello"] = "world"
    return attr

class MetaHachoir(Script):
  def __init__(self):
    Script.__init__(self, "metahachoir")
    self.handler = HachoirHandler()

  def start(self, args):
    try:
      node = args['file'].value();
      self.stateinfo = "Registering node: " + str(node.name())
      node.registerAttributes(self.handler)
    except KeyError:
      pass

class metahachoir(Module): 
  """This modules generate Word metadata in node attributes"""
  def __init__(self):
    Module.__init__(self, "metahachoir", MetaHachoir)
    self.conf.addArgument({"name": "file",
                           "description": "file for extracting metadata",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["doc", "docx"]})
    self.flags = ["single"]
    self.tags = "Metadata"
