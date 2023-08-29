from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.awt.event import ActionListener
import re

# Welcome message
print("Welcome to the Redacted Request Extension v1.0 by OME MISHRA!")
print("Copyright (c) 2023 OME MISHRA. All rights reserved.")
print("This code is protected by copyright law. Unauthorized copying or distribution is prohibited.")

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set the extension name
        callbacks.setExtensionName("Redacted Request")

        # Register the context menu factory
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        selectedMessages = invocation.getSelectedMessages()
        if len(selectedMessages) == 1:
            menuItems = []
            menuItem = JMenuItem("Copy Redacted Request")
            menuItem.addActionListener(self.MenuItemClickListener(self._helpers, selectedMessages[0]))
            menuItems.append(menuItem)
            return menuItems
        return None

    class MenuItemClickListener(ActionListener):
        def __init__(self, helpers, selectedMessage):
            self._helpers = helpers
            self._selectedMessage = selectedMessage

        def actionPerformed(self, e):
            request = self._selectedMessage.getRequest()
            requestBytes = self._helpers.bytesToString(request)
            
            # Redact the Cookie header
            modifiedRequestBytes = re.sub(r'Cookie: .*', 'Cookie: Redacted', requestBytes)
            
            # Redact the Authorization header
            modifiedRequestBytes = re.sub(r'Authorization: .*', 'Authorization: Redacted', modifiedRequestBytes)
            
            # Redact the X-Amz-Security-Token header
            modifiedRequestBytes = re.sub(r'X-Amz-Security-Token: .*', 'X-Amz-Security-Token: Redacted', modifiedRequestBytes)
            
            stringSelection = StringSelection(modifiedRequestBytes)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(stringSelection, None)
            print("Request copied to clipboard.")

if __name__ in ["__main__", "burp"]:
    BurpExtender()
