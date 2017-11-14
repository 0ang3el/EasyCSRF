try:
    from burp import IBurpExtender
    from burp import IProxyListener
    from burp import IParameter
    from burp import IRequestInfo
    from burp import IInterceptedProxyMessage
    from burp import ITab
    from javax.swing import JLabel
    from javax.swing import JPanel
    from javax.swing import JCheckBox
    from java.awt import GridBagLayout
    from java.awt import GridBagConstraints
    from java.awt import Insets
    from java.awt import Color
    from java.awt import Font
    import re
    from urlparse import parse_qs
    from json import dumps
except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

callbacks = None
helpers = None
NAME = "EasyCSRF"
VERSION = "1.0"
DEBUG = False

extension_enable = True
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

def filter_headers(headers):
    _headers = headers[:]
    for header in headers:
        for csrf_header in csrf_headers_names:
            if header.lower().startswith(csrf_header.lower()):
                _headers.remove(header)

    return _headers

class BurpExtender(IBurpExtender, IProxyListener, ITab):
    def getTabCaption(self):  ### ITab
        return NAME

    def getUiComponent(self):  ### ITab
        return self.settings

    def registerExtenderCallbacks(self, this_callbacks):  ### IBurpExtender
        global callbacks, helpers
        global extension_enable
        global remove_csrf_headers, remove_csrf_params, change_method_to_post
        global change_ct_to_json, change_ct_to_plain, change_to_get

        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName(NAME)

        self.settings = JPanel(GridBagLayout())
        c = GridBagConstraints()

        self.extension_enable_box = JCheckBox('Enable extension', extension_enable)
        self.extension_enable_box.setFont(Font("Serif", Font.BOLD, 20))
        self.extension_enable_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 0
        c.gridwidth = 1
        c.weightx = 1
        c.fill = GridBagConstraints.NONE
        c.anchor = GridBagConstraints.WEST
        self.settings.add(self.extension_enable_box, c)

        self.remove_csrf_headers_box = JCheckBox('Remove CSRF headers', remove_csrf_params)
        self.remove_csrf_headers_box.setFont(Font("Serif", Font.BOLD, 20))
        self.remove_csrf_headers_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(40, 5, 5, 5)
        c.gridx = 0
        c.gridy = 1
        self.settings.add(self.remove_csrf_headers_box, c)

        remove_csrf_headers_box_lbl = JLabel('Check to remove headers with CSRF tokens from all requests.')
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 2
        self.settings.add(remove_csrf_headers_box_lbl, c)

        self.remove_csrf_params_box = JCheckBox('Remove CSRF parameters', remove_csrf_params)
        self.remove_csrf_params_box.setFont(Font("Serif", Font.BOLD, 20))
        self.remove_csrf_params_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 3
        self.settings.add(self.remove_csrf_params_box, c)

        remove_csrf_params_box_lbl = JLabel('Check to remove URL/body parameters with CSRF tokens from all requests. URL-encoded, multipart, JSON parameters are supported.')
        c.gridx = 0
        c.gridy = 4
        self.settings.add(remove_csrf_params_box_lbl, c)

        self.change_method_to_post_box = JCheckBox('Change HTTP method to POST', change_method_to_post)
        self.change_method_to_post_box.setFont(Font("Serif", Font.BOLD, 20))
        self.change_method_to_post_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 5
        self.settings.add(self.change_method_to_post_box, c)

        change_method_to_post_lbl = JLabel('Check to convert PUT/DELETE/PATCH method to POST in all requests.')
        c.gridx = 0
        c.gridy = 6
        self.settings.add(change_method_to_post_lbl, c)

        self.change_ct_to_json_box = JCheckBox('Change media type to json', change_ct_to_json)
        self.change_ct_to_json_box.setFont(Font("Serif", Font.BOLD, 20))
        self.change_ct_to_json_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 7
        self.settings.add(self.change_ct_to_json_box, c)

        change_ct_to_json_lbl = JLabel('Check to convert body to json and set Content-Type to application/json in url-encoded requests.')
        c.gridx = 0
        c.gridy = 8
        self.settings.add(change_ct_to_json_lbl, c)

        self.change_ct_to_plain_box = JCheckBox('Change Content-Type to text/plain', change_ct_to_plain)
        self.change_ct_to_plain_box.setFont(Font("Serif", Font.BOLD, 20))
        self.change_ct_to_plain_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 9
        self.settings.add(self.change_ct_to_plain_box, c)

        change_ct_to_plain_lbl = JLabel('Check to set Content-Type to text/plain in request with non-simple media type. Simple media types - application/application/x-www-form-urlencoded, text/plain, multipart/form-data.')
        c.gridx = 0
        c.gridy = 10
        self.settings.add(change_ct_to_plain_lbl, c)

        self.change_to_get_box = JCheckBox('Change to GET', change_to_get)
        self.change_to_get_box.setFont(Font("Serif", Font.BOLD, 20))
        self.change_to_get_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 11
        self.settings.add(self.change_to_get_box, c)

        change_to_get_lbl = JLabel('Check to convert POST/PUT/DELETE/PATCH url-encoded requests to GET.')
        c.gridx = 0
        c.gridy = 12
        self.settings.add(change_to_get_lbl, c)

        callbacks.customizeUiComponent(self.settings)
        callbacks.addSuiteTab(self)

        callbacks.registerProxyListener(self)

        print "Successfully loaded %s v%s" % (NAME, VERSION)

    def processProxyMessage(self, messageIsRequest, message):  ### IProxyListener
        extension_enable = self.extension_enable_box.isSelected()
        if not extension_enable:
            return  # Do nothing

        remove_csrf_headers = self.remove_csrf_headers_box.isSelected()
        remove_csrf_params = self.remove_csrf_params_box.isSelected()
        change_method_to_post = self.change_method_to_post_box.isSelected()
        change_ct_to_json = self.change_ct_to_json_box.isSelected()
        change_ct_to_plain = self.change_ct_to_plain_box.isSelected()
        change_to_get = self.change_to_get_box.isSelected()

        request_response = message.getMessageInfo()
        request_info = helpers.analyzeRequest(request_response)
        request_method = request_info.getMethod()

        if not messageIsRequest or request_method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return  # Do nothing

        http_service = request_response.getHttpService()
        request = request_response.getRequest()
        headers = request_info.getHeaders()
        parameters = request_info.getParameters()

        new_headers = headers
        if remove_csrf_headers:
            new_headers = filter_headers(headers)  # Remove CSRF headers

        if change_ct_to_plain and request_info.getContentType() not in [IRequestInfo.CONTENT_TYPE_URL_ENCODED, IRequestInfo.CONTENT_TYPE_MULTIPART]:
            for i in range(len(new_headers)):
                if new_headers[i].lower().startswith('content-type'):  # Change CT to text/plain
                    new_headers[i] = 'Content-Type: text/plain'

        if remove_csrf_params:
            for parameter in parameters:  # Remove CSRF parameters from request's body or URL
                for csrf_param in csrf_params_names:
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

        if change_method_to_post or (change_to_get and not change_ct_to_json and \
                                request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED):
            for i in range(len(new_headers)):
                if new_headers[i].startswith("PUT") or new_headers[i].startswith("DELETE") \
                        or new_headers[i].startswith("PATCH"):
                    new_headers[i] = new_headers[i].replace(request_method, 'POST', 1)
                    break

        new_request = helpers.buildHttpMessage(new_headers, body)  # Create new request with valid Content-Length

        if change_to_get and not change_ct_to_json and request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
            new_request = helpers.toggleRequestMethod(new_request)  # Change any URL-encoded request to GET

        message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK)
        message.getMessageInfo().setRequest(new_request)
        message.getMessageInfo().setHighlight('red')