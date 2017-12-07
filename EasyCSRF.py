try:
    from burp import IBurpExtender
    from burp import IProxyListener
    from burp import IParameter
    from burp import IRequestInfo
    from burp import IInterceptedProxyMessage
    from burp import IContextMenuFactory
    from burp import IContextMenuInvocation
    from burp import ITab
    from javax.swing import JMenuItem
    from javax.swing import JLabel
    from javax.swing import JButton
    from javax.swing import JTextArea
    from javax.swing import JTextField
    from javax.swing import JPanel
    from javax.swing import JScrollPane
    from javax.swing import JCheckBox
    from javax.swing import JTabbedPane
    from javax.swing.text import Utilities
    from javax.swing.text import DefaultHighlighter
    from java.awt import GridBagLayout
    from java.awt import GridBagConstraints
    from java.awt import Insets
    from java.awt import Color
    from java.awt import Font
    from java.awt.event import MouseEvent
    from java.awt.event import MouseAdapter
    import re
    import os
    from urlparse import parse_qs, urlparse
    from json import dumps
except ImportError:
    print 'Failed to load dependencies. This issue maybe caused by using an unstable Jython version.'

callbacks = None
helpers = None
NAME = 'EasyCSRF'
VERSION = '2.0'
DEBUG = False

extension_enable = True
in_scope_only = True
remove_csrf_headers = True
remove_csrf_params = True
change_method_to_post = True
change_ct_to_json = True
change_ct_to_plain = False
change_to_get = False

csrf_headers_names = [  # Headers that may contain CSRF tokens
    "X-XSRF-TOKEN",
    "X-CSRF-TOKEN",
    "CSRF-TOKEN",
    "XSRF-TOKEN",
    "Authorization",
    "Origin"
]

csrf_params_names = [  # Parameters that may contain CSRF tokens
    "csrf",
    "xsrf",
    "token",
    "auth",
    "secret"
]

def debug2console(title, *args):
    if DEBUG:
        print "[ debug ]", "Begin", title
        for arg in args:
            print arg
        print "[ debug ]", "End", title

def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''

    return helpers.bytesToString(bytes)

class BurpExtender(IBurpExtender, IProxyListener, ITab):
    def getTabCaption(self):  ### ITab
        return NAME

    def getUiComponent(self):  ### ITab
        return self.tabs

    def setFontItalic(self, label):
        label.setFont(Font(label.getFont().getName(), Font.ITALIC, label.getFont().getSize()))

    def setFontBold(self, label):
        label.setFont(Font('Serif', Font.BOLD, label.getFont().getSize()))

    def registerExtenderCallbacks(self, this_callbacks):  ### IBurpExtender
        global callbacks, helpers
        global extension_enable, in_scope_only
        global remove_csrf_headers, remove_csrf_params, change_method_to_post
        global change_ct_to_json, change_ct_to_plain, change_to_get

        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName(NAME)

        self.settings = JPanel(GridBagLayout())
        c = GridBagConstraints()

        self.extension_enable_box = JCheckBox('Enable extension', extension_enable)
        self.setFontBold(self.extension_enable_box)
        self.extension_enable_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 0
        c.gridwidth = 1
        c.weightx = 1
        c.fill = GridBagConstraints.NONE
        c.anchor = GridBagConstraints.WEST
        self.settings.add(self.extension_enable_box, c)

        self.in_scope_only_box = JCheckBox('Modify only in-scope requests', in_scope_only)
        self.setFontBold(self.in_scope_only_box)
        self.in_scope_only_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(40, 5, 5, 5)
        c.gridx = 0
        c.gridy = 1
        self.settings.add(self.in_scope_only_box, c)

        self.remove_csrf_headers_box = JCheckBox('Remove CSRF headers', remove_csrf_params)
        self.setFontBold(self.remove_csrf_headers_box)
        self.remove_csrf_headers_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(40, 5, 5, 5)
        c.gridx = 0
        c.gridy = 2
        self.settings.add(self.remove_csrf_headers_box, c)

        remove_csrf_headers_box_lbl = JLabel('Check to remove headers with CSRF tokens from all requests.')
        self.setFontItalic(remove_csrf_headers_box_lbl)
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 3
        self.settings.add(remove_csrf_headers_box_lbl, c)

        self.remove_csrf_params_box = JCheckBox('Remove CSRF parameters', remove_csrf_params)
        self.setFontBold(self.remove_csrf_params_box)
        self.remove_csrf_params_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 4
        self.settings.add(self.remove_csrf_params_box, c)

        remove_csrf_params_box_lbl = JLabel('Check to remove URL/body parameters with CSRF tokens from all requests. URL-encoded, multipart, JSON parameters are supported.')
        self.setFontItalic(remove_csrf_params_box_lbl)
        c.gridx = 0
        c.gridy = 5
        self.settings.add(remove_csrf_params_box_lbl, c)

        self.change_method_to_post_box = JCheckBox('Change HTTP method to POST', change_method_to_post)
        self.setFontBold(self.change_method_to_post_box)
        self.change_method_to_post_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 6
        self.settings.add(self.change_method_to_post_box, c)

        change_method_to_post_lbl = JLabel('Check to convert PUT/DELETE/PATCH method to POST in all requests.')
        self.setFontItalic(change_method_to_post_lbl)
        c.gridx = 0
        c.gridy = 7
        self.settings.add(change_method_to_post_lbl, c)

        self.change_ct_to_json_box = JCheckBox('Change media type to json', change_ct_to_json)
        self.setFontBold(self.change_ct_to_json_box)
        self.change_ct_to_json_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 8
        self.settings.add(self.change_ct_to_json_box, c)

        change_ct_to_json_lbl = JLabel('Check to convert body to json and set Content-Type to application/json in url-encoded requests.')
        self.setFontItalic(change_ct_to_json_lbl)
        c.gridx = 0
        c.gridy = 9
        self.settings.add(change_ct_to_json_lbl, c)

        self.change_ct_to_plain_box = JCheckBox('Change Content-Type to text/plain', change_ct_to_plain)
        self.setFontBold(self.change_ct_to_plain_box)
        self.change_ct_to_plain_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 10
        self.settings.add(self.change_ct_to_plain_box, c)

        change_ct_to_plain_lbl = JLabel('Check to set Content-Type to text/plain in request with non-simple media type. Simple media types - application/application/x-www-form-urlencoded, text/plain, multipart/form-data.')
        self.setFontItalic(change_ct_to_plain_lbl)
        c.gridx = 0
        c.gridy = 11
        self.settings.add(change_ct_to_plain_lbl, c)

        self.change_to_get_box = JCheckBox('Change to GET', change_to_get)
        self.setFontBold(self.change_to_get_box)
        self.change_to_get_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 12
        self.settings.add(self.change_to_get_box, c)

        change_to_get_lbl = JLabel('Check to convert POST/PUT/DELETE/PATCH url-encoded requests to GET.')
        self.setFontItalic(change_to_get_lbl)
        c.gridx = 0
        c.gridy = 13
        self.settings.add(change_to_get_lbl, c)

        self.csrf_headers_params = JPanel(GridBagLayout())
        c = GridBagConstraints()

        lblParams = JLabel("CSRF parameters:")
        self.setFontBold(lblParams)
        lblParams.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 0
        c.insets = Insets(5, 5, 5, 5)
        c.fill = GridBagConstraints.NONE
        c.anchor = GridBagConstraints.FIRST_LINE_END
        self.csrf_headers_params.add(lblParams, c)

        self.csrf_param_text_field = JTextField()
        c.fill = GridBagConstraints.BOTH
        c.gridx = 1
        c.gridy = 0
        self.csrf_headers_params.add(self.csrf_param_text_field, c)

        lblParamsNote = JLabel("Remove parameter from request if name contains")
        self.setFontItalic(lblParamsNote)
        c.fill = GridBagConstraints.NONE
        c.gridx = 0
        c.gridy = 1
        self.csrf_headers_params.add(lblParamsNote, c)

        self.csrf_params_text_area = JTextArea()
        self.csrf_params_text_area.setColumns(20)
        self.csrf_params_text_area.setRows(10)
        self.csrf_params_text_area.setEditable(False)
        c.fill = GridBagConstraints.BOTH
        self.csrf_params_mouse_listener = TextAreaMouseListener(self.csrf_params_text_area)
        self.csrf_params_text_area.addMouseListener(self.csrf_params_mouse_listener)
        for name in csrf_params_names:
            self.csrf_params_text_area.append(name + os.linesep)
        c.gridx = 1
        c.gridy = 1
        sp = JScrollPane(self.csrf_params_text_area)
        self.csrf_headers_params.add(sp, c)

        buttonsPanel = JPanel(GridBagLayout())
        _c = GridBagConstraints()
        _c.insets = Insets(3, 3, 3, 3)
        _c.gridx = 0
        _c.gridy = 0
        _c.fill = GridBagConstraints.BOTH
        _c.weightx = 1
        _c.gridwidth = 1

        handlers = ButtonHandlers(self.csrf_param_text_field, self.csrf_params_text_area, self.csrf_params_mouse_listener, csrf_params_names)
        self.csrf_param_add_button = JButton('Add', actionPerformed=handlers.handler_add)
        self.csrf_param_rm_button = JButton('Remove', actionPerformed=handlers.handler_rm)
        self.csrf_param_restore_button = JButton('Restore', actionPerformed=handlers.handler_restore)
        buttonsPanel.add(self.csrf_param_add_button, _c)
        _c.gridy = 1
        buttonsPanel.add(self.csrf_param_rm_button, _c)
        _c.gridy = 2
        buttonsPanel.add(self.csrf_param_restore_button, _c)
        _c.gridy = 3

        c.gridx = 2
        c.gridy = 1
        c.fill = GridBagConstraints.NONE
        self.csrf_headers_params.add(buttonsPanel, c)

        lblHeaders = JLabel("CSRF headers:")
        self.setFontBold(lblHeaders)
        lblHeaders.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 2
        c.insets = Insets(40, 5, 5, 5)
        c.fill = GridBagConstraints.NONE
        c.anchor = GridBagConstraints.FIRST_LINE_END
        self.csrf_headers_params.add(lblHeaders, c)

        self.csrf_header_text_field = JTextField()
        c.fill = GridBagConstraints.BOTH
        c.gridx = 1
        c.gridy = 2
        self.csrf_headers_params.add(self.csrf_header_text_field, c)

        lblHeadersNote = JLabel("Remove header from request if name equals to")
        self.setFontItalic(lblHeadersNote)
        c.fill = GridBagConstraints.NONE
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 3
        self.csrf_headers_params.add(lblHeadersNote, c)

        self.csrf_headers_text_area = JTextArea()
        self.csrf_headers_text_area.setColumns(20)
        self.csrf_headers_text_area.setRows(10)
        self.csrf_headers_text_area.setEditable(False)
        c.fill = GridBagConstraints.BOTH
        self.csrf_headers_mouse_listener = TextAreaMouseListener(self.csrf_headers_text_area)
        self.csrf_headers_text_area.addMouseListener(self.csrf_headers_mouse_listener)
        for name in csrf_headers_names:
            self.csrf_headers_text_area.append(name + os.linesep)
        c.gridx = 1
        c.gridy = 3
        sp = JScrollPane(self.csrf_headers_text_area)
        self.csrf_headers_params.add(sp, c)

        buttonsPanel = JPanel(GridBagLayout())
        _c = GridBagConstraints()
        _c.insets = Insets(3, 3, 3, 3)
        _c.gridx = 0
        _c.gridy = 0
        _c.fill = GridBagConstraints.BOTH
        _c.weightx = 1
        _c.gridwidth = 1

        handlers = ButtonHandlers(self.csrf_header_text_field, self.csrf_headers_text_area, self.csrf_headers_mouse_listener, csrf_headers_names)
        self.csrf_header_add_button = JButton('Add', actionPerformed=handlers.handler_add)
        self.csrf_header_rm_button = JButton('Remove', actionPerformed=handlers.handler_rm)
        self.csrf_header_restore_button = JButton('Restore', actionPerformed=handlers.handler_restore)
        buttonsPanel.add(self.csrf_header_add_button, _c)
        _c.gridy = 1
        buttonsPanel.add(self.csrf_header_rm_button, _c)
        _c.gridy = 2
        buttonsPanel.add(self.csrf_header_restore_button, _c)
        _c.gridy = 3

        c.gridx = 2
        c.gridy = 3
        c.fill = GridBagConstraints.NONE
        self.csrf_headers_params.add(buttonsPanel, c)

        self.whitelist = JPanel(GridBagLayout())
        c = GridBagConstraints()

        lblWhitelist = JLabel("URLs whitelist:")
        self.setFontBold(lblWhitelist)
        lblWhitelist.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 0
        c.insets = Insets(5, 5, 5, 5)
        c.fill = GridBagConstraints.NONE
        c.anchor = GridBagConstraints.FIRST_LINE_END
        self.whitelist.add(lblWhitelist, c)

        self.whitelist_text_field = JTextField()
        c.fill = GridBagConstraints.BOTH
        c.gridx = 1
        c.gridy = 0
        self.whitelist.add(self.whitelist_text_field, c)

        lblWhitelistNote = JLabel("Do not perform request modification if URL starts with")
        self.setFontItalic(lblWhitelistNote)
        c.fill = GridBagConstraints.NONE
        c.gridx = 0
        c.gridy = 1
        self.whitelist.add(lblWhitelistNote, c)

        self.whitelist_text_area = JTextArea()
        self.whitelist_text_area.setColumns(30)
        self.whitelist_text_area.setRows(10)
        self.whitelist_text_area.setEditable(False)
        c.fill = GridBagConstraints.BOTH
        self.whitelist_mouse_listener = TextAreaMouseListener(self.whitelist_text_area)
        self.whitelist_text_area.addMouseListener(self.whitelist_mouse_listener)
        c.gridx = 1
        c.gridy = 1
        sp = JScrollPane(self.whitelist_text_area)
        self.whitelist.add(sp, c)

        buttonsPanel = JPanel(GridBagLayout())
        _c = GridBagConstraints()
        _c.insets = Insets(3, 3, 3, 3)
        _c.gridx = 0
        _c.gridy = 0
        _c.fill = GridBagConstraints.BOTH
        _c.weightx = 1
        _c.gridwidth = 1

        handlers = ButtonHandlers(self.whitelist_text_field, self.whitelist_text_area,
                                  self.whitelist_mouse_listener, [])
        self.whitelist_add_button = JButton('Add', actionPerformed=handlers.handler_add)
        self.whitelist_rm_button = JButton('Remove', actionPerformed=handlers.handler_rm)
        self.whitelist_clear_button = JButton('Clear', actionPerformed=handlers.handler_restore)
        buttonsPanel.add(self.whitelist_add_button, _c)
        _c.gridy = 1
        buttonsPanel.add(self.whitelist_rm_button, _c)
        _c.gridy = 2
        buttonsPanel.add(self.whitelist_clear_button, _c)
        _c.gridy = 3

        c.gridx = 2
        c.gridy = 1
        c.fill = GridBagConstraints.NONE
        self.whitelist.add(buttonsPanel, c)

        self.tabs = JTabbedPane()
        self.tabs.addTab('Settings', self.settings)
        self.tabs.addTab('CSRF params/headers to remove', self.csrf_headers_params)
        self.tabs.addTab('Requests whitelist', self.whitelist)

        callbacks.customizeUiComponent(self.tabs)
        callbacks.addSuiteTab(self)

        callbacks.registerProxyListener(self)

        callbacks.registerContextMenuFactory(SendToWhitelist(self.whitelist_text_area))

        print "Successfully loaded %s v%s by Mikhail Egorov @0ang3el" % (NAME, VERSION)

    def text_area_to_list(self, text_area):
        l = text_area.getText().strip().split('\n')
        return l if l != [''] else []

    def filter_headers(self, headers):
        _headers = headers[:]
        for header in headers:
            for csrf_header in self.text_area_to_list(self.csrf_headers_text_area):
                if header.lower().startswith(csrf_header.lower()):
                    _headers.remove(header)

        return _headers

    def processProxyMessage(self, messageIsRequest, message):  ### IProxyListener
        global callbacks
        extension_enable = self.extension_enable_box.isSelected()
        if not extension_enable:
            return  # Do nothing

        in_scope_only = self.in_scope_only_box.isSelected()

        remove_csrf_headers = self.remove_csrf_headers_box.isSelected()
        remove_csrf_params = self.remove_csrf_params_box.isSelected()
        change_method_to_post = self.change_method_to_post_box.isSelected()
        change_ct_to_json = self.change_ct_to_json_box.isSelected()
        change_ct_to_plain = self.change_ct_to_plain_box.isSelected()
        change_to_get = self.change_to_get_box.isSelected()

        request_response = message.getMessageInfo()
        request_info = helpers.analyzeRequest(request_response)
        request_method = request_info.getMethod()

        if in_scope_only and not callbacks.isInScope(request_info.getUrl()):
            return  # Do nothing when URL is not in scope

        if not messageIsRequest or request_method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return  # Do nothing

        for whitelisted in self.text_area_to_list(self.whitelist_text_area):
            if str(request_info.getUrl()).startswith(whitelisted):
                return # Do nothing when URL is whitelisted

        http_service = request_response.getHttpService()
        request = request_response.getRequest()
        headers = request_info.getHeaders()
        parameters = request_info.getParameters()

        new_headers = headers
        if remove_csrf_headers:
            new_headers = self.filter_headers(headers)  # Remove CSRF headers

        if change_ct_to_plain and request_info.getContentType() not in [IRequestInfo.CONTENT_TYPE_URL_ENCODED, IRequestInfo.CONTENT_TYPE_MULTIPART]:
            for i in range(len(new_headers)):
                if new_headers[i].lower().startswith('content-type'):  # Change CT to text/plain
                    new_headers[i] = 'Content-Type: text/plain'

        if remove_csrf_params:
            for parameter in parameters:  # Remove CSRF parameters from request's body or URL
                for csrf_param in self.text_area_to_list(self.csrf_params_text_area):
                    if parameter.getType() != IParameter.PARAM_COOKIE and \
                            csrf_param.lower() in parameter.getName().lower():
                        if request_info.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART:
                            start = parameter.getNameStart()
                            end = parameter.getNameEnd()

                            request = request[:start] + helpers.stringToBytes("REPLACEMENT") + request[end:]
                        elif parameter.getType() == IParameter.PARAM_JSON:
                            start = parameter.getNameStart() - 1
                            end = parameter.getValueEnd() + 1
                            request = request[:start] + request[end:]

                            offset = helpers.analyzeRequest(http_service, request).getBodyOffset()
                            body = request[offset:]
                            body = re.sub(",\s*,", ",", body)
                            body = re.sub("{\s*,", "{", body)
                            body = re.sub(",\s*}", "}", body)

                            request = helpers.buildHttpMessage(headers, body)
                        elif parameter.getType() in [IParameter.PARAM_URL, IParameter.PARAM_BODY]:
                            request = helpers.removeParameter(request, parameter)

        offset = helpers.analyzeRequest(http_service, request).getBodyOffset()
        body = request[offset:]

        if change_ct_to_json and request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
            for i in range(len(new_headers)):
                if new_headers[i].lower().startswith('content-type'):  # Change to JSON from URL-encoded
                    new_headers[i] = 'Content-Type: application/json'

            body = safe_bytes_to_string(body)
            d = dict((k, v if len(v) > 1 else v[0]) for k, v in parse_qs(body).iteritems())
            body = dumps(d)

        if (change_method_to_post and request_method != 'POST') or (change_to_get and not change_ct_to_json and \
                                request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED):
            for i in range(len(new_headers)):
                if new_headers[i].startswith("PUT") or new_headers[i].startswith("DELETE") \
                        or new_headers[i].startswith("PATCH"):
                    new_headers[i] = new_headers[i].replace(request_method, 'POST', 1)
                    break

        new_request = helpers.buildHttpMessage(new_headers, body)  # Create new request with valid Content-Length

        if (change_method_to_post and request_method != 'POST') or (change_to_get and not change_ct_to_json and \
                                request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED):
            param1 = helpers.buildParameter('method', request_method, IParameter.PARAM_URL)
            param2 = helpers.buildParameter('_method', request_method, IParameter.PARAM_URL)
            new_request = helpers.addParameter(new_request, param1)
            new_request = helpers.addParameter(new_request, param2)
            if change_to_get:
                new_request = helpers.toggleRequestMethod(new_request)  # Change any URL-encoded request to GET

        message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK)
        message.getMessageInfo().setRequest(new_request)
        message.getMessageInfo().setHighlight('red')

class TextAreaMouseListener(MouseAdapter):
    def __init__(self, text_area):
        self.text_area = text_area

    def getSelected(self):
        return (self.start, self.value)

    def mousePressed(self, event):  ### MouseAdapter
        if event.getButton() != MouseEvent.BUTTON1:
            return

        offset = self.text_area.viewToModel(event.getPoint())
        rowStart = Utilities.getRowStart(self.text_area, offset)
        rowEnd = Utilities.getRowEnd(self.text_area, offset)
        self.start = rowStart
        self.value = self.text_area.getText()[rowStart: rowEnd]

        self.text_area.getHighlighter().removeAllHighlights()
        painter = DefaultHighlighter.DefaultHighlightPainter(Color.LIGHT_GRAY)
        self.text_area.getHighlighter().addHighlight(rowStart, rowEnd, painter)

class SendToWhitelist(IContextMenuFactory):
    def __init__(self, whitelist_text_area):
        self.whitelist_text_area = whitelist_text_area

    def add_to_whitelist(self, event):
        self.whitelist_text_area.append(self.value + os.linesep)

    def createMenuItems(self, invocation):   ### IContextMenuFactory
        if not invocation.getInvocationContext() in (IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
                                                     IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST):
            return

        try:
            start, end = invocation.getSelectionBounds()
        except:
            return []

        request_response = invocation.getSelectedMessages()[0]

        info = helpers.analyzeRequest(request_response)
        request = safe_bytes_to_string(request_response.getRequest())

        url = urlparse(str(info.getUrl()))

        selected = request[start:end].strip()
        query_index = selected.find('?')
        selected = selected[:query_index] if query_index != -1 else selected
        if not url.path.startswith(selected) or start == end:
            return []

        self.value = url.scheme + '://' + url.netloc + selected

        add_to_whitelist_menu_item = JMenuItem('>> Add to EasyCSRF whitelist <<')
        add_to_whitelist_menu_item.addActionListener(self.add_to_whitelist)

        return [add_to_whitelist_menu_item]

class ButtonHandlers:
    def __init__(self, text_field, text_area, mouse_listener, default_values):
        self.text_field = text_field
        self.text_area = text_area
        self.mouse_listener = mouse_listener
        self.default_values = default_values

    def handler_add(self, event):
        name = self.text_field.getText()
        self.text_area.append(name + os.linesep)
        self.text_field.setText('')

    def handler_rm(self, event):
        self.text_field.setText('')
        start, value = self.mouse_listener.getSelected()
        end = start + len(value)
        text_area = self.text_area.getText()
        text_area = (text_area[:start] + text_area[end:]).strip('\n').replace('\n\n', '\n')
        self.text_area.setText(text_area)

    def handler_restore(self, event):
        self.text_field.setText('')
        self.text_area.setText('')
        for name in self.default_values:
            self.text_area.append(name + os.linesep)