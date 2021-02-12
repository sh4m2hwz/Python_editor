# Created by: Storm Shadow http://www.techbliss.org
import os
import ida_idaapi, ida_kernwin
import idc
import idaapi
import idautils
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0 , os.path.join(ROOT_DIR, "Code editor", "icons")) # so later we can import ico

import ico

PLUGIN_VERSION = "3.0"
IDAVERISONS    = "IDA PRO 7.4+"
AUTHORS        = "Storm Shadow, bruce30262"
DATE           = "2021"
TWITTER        = "Twitter @zadow28 @bruce30262"

def banner():
    banner_options = (PLUGIN_VERSION, AUTHORS, DATE, TWITTER, IDAVERISONS)
    banner_titles = "Python Editor v%s - (c) %s - %s - %s - %s" % banner_options
    print("---[" + banner_titles + "]---\n")

banner()

# 1) Create the handler class
class MyEditorHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Run editor when invoked.
    def activate(self, ctx):
        g = globals()
        idahome = os.path.join(ROOT_DIR, "Code editor")
        idaapi.IDAPython_ExecScript(os.path.join(idahome, "pyeditor.py"), g)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ripeye(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Run me"
    help = "Python Editor"
    wanted_name = "Python Editor"
    wanted_hotkey = "" #the tooltip horkey goes away when setting it here DONT DO it! and only is shown in File/Plugins menu


    def editor_menuaction(self):
        action_desc = idaapi.action_desc_t(
            'my:editoraction',  # The action name. This acts like an ID and must be unique
            'Python Editor!',  # The action text.
            MyEditorHandler(),  # The action handler.
            'Ctrl+H',  # Optional: the action shortcut DO IT  HERE!
            'Script editor',  # Optional: the action tooltip (available in menus/toolbar)
            idaapi.load_custom_icon(":/ico/python.png")  # hackish load action icon , if no custom icon use number from 1-150 from internal ida
        )

        # 3) Register the action
        idaapi.register_action(action_desc)

        idaapi.attach_action_to_menu(
            'File/Editor...',  # The relative path of where to add the action
            'my:editoraction',  # The action ID (see above)
            idaapi.SETMENU_APP)  # We want to append the action after the 'Manual instruction...

        form = ida_kernwin.get_current_widget()
        idaapi.attach_action_to_popup(form, None, "my:editoraction", None)

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        # attempt plugin initialization
        try:
            self._install_plugin()

        # failed to initialize or integrate the plugin, log and skip loading
        except Exception as e:
            form = ida_kernwin.get_current_widget()
            pass

        return idaapi.PLUGIN_KEEP


    def _install_plugin(self):
        """
        Initialize & integrate the plugin into IDA.
        """
        self.editor_menuaction()
        self._init()

    def term(self):
        pass

    def run(self, arg = 0):
        #we need the calls again if we wanna load it via File/Plugins/editor
        idaapi.msg("Python Editor Loaded to menu \n use Alt+E hot key to quick load ")
        hackish = MyEditorHandler()
        hackish.activate(self)

def PLUGIN_ENTRY():
    return ripeye()
