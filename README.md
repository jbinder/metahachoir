metahachoir
===========

Module for the Digital Forensics Framework (DFF) to show metadata provided by hachoir-metadata in the node attributes.


Requirements
------------

*   Digital Forensics Framework 1.3.0 (http://www.digital-forensic.org/)
*   python-hachoir-metadata 1.3.3 (https://bitbucket.org/haypo/hachoir/)


Install
-------

*   get the DFF source: http://wiki.digital-forensic.org/index.php/Installation
*   install python-hachoir-metadata: https://bitbucket.org/haypo/hachoir/wiki/Install
*   checkout metahachoir into [dff-root-dir]/dff/modules/metadata/
*   add `add_subdirectory (metahachoir)` to [dff-root-dir]/dff/modules/metadata/CMakeLists.txt
*   build DFF: http://wiki.digital-forensic.org/index.php/Installation


History
-------

v1.0.1
updated for DFF 1.3.0

v1.0.0
initial release for DFF 1.2.0

Todo
----

*   improve performance and memory requirements by passing a stream to the hachoir parser instead of the whole content

