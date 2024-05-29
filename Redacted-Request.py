from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.awt.event import ActionListener
import re
import json

# Welcome message
print("Welcome to the Redacted Request Extension v1.1 by OME MISHRA!")
print("Copyright (c) 2024 OME MISHRA. All rights reserved.")
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
    
            # Define sensitive information to redact
            sensitive_info = ['Cookie', 'Authorization', 'X-Amz-Security-Token', 'Email', 'Username', 'Password', 'Token', 'Key', 'Apikey']
    
            # Redact sensitive information
            modifiedRequestBytes = requestBytes
            for info in sensitive_info:
            
                # With Headers
                modifiedRequestBytes = re.sub(info + r': .*', info + ': Redacted', modifiedRequestBytes)
                
                #Body Plain
                modifiedRequestBytes = re.sub(info.lower() + r'=.*', info.lower() + '=Redacted', modifiedRequestBytes)
                
            # With JSON
            try:
                # Split the request body 
                header_end_index = modifiedRequestBytes.index('\r\n\r\n') + 4
                header_section = modifiedRequestBytes[:header_end_index]
                body_section = modifiedRequestBytes[header_end_index:]

                # Attempt to parse the body 
                json_data = json.loads(body_section)

                # Redact sensitive information 
                for key in json_data:
                    if key.lower() in [info.lower() for info in sensitive_info]:
                        json_data[key] = 'Redacted'

                # Combine headers and redacted JSON data
                modifiedRequestBytes = header_section + json.dumps(json_data)
            except ValueError:
                pass  # Ignore if the request body is not JSON or cannot be parsed

    
            stringSelection = StringSelection(modifiedRequestBytes)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(stringSelection, None)
            print("Request copied to clipboard.")   

if __name__ in ["__main__", "burp"]:
    BurpExtender()
