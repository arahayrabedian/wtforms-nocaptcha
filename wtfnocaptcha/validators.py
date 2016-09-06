import logging
import json

try:
    from urllib.request import ProxyHandler, urlopen, build_opener, \
        install_opener
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x compatible import
    from urllib2 import ProxyHandler, urlopen, build_opener, install_opener
    from urllib import urlencode

from wtforms.validators import ValidationError


logger = logging.getLogger(__name__)


class NoCaptcha(object):
    """Validates captcha by using reCaptcha API"""

    # Mapping of response error codes
    errors = {
        'missing-input-secret': 'The secret parameter is missing.',
        'invalid-input-secret':	'The secret parameter is invalid or malformed.',
        'missing-input-response': 'The response parameter is missing.',
        'invalid-input-response': 'The response parameter is invalid or malformed.',
        'nocaptcha-not-reachable': 'Could not connect to nocaptcha api',
    }

    empty_error_text = u'This field is required'
    internal_error_text = u'Internal error, please try again later'

    def _call_verify(self, params, proxy):
        """Performs a call to reCaptcha API with given params"""
        data = []
        if proxy:
            proxy_handler = ProxyHandler({'http': proxy})
            opener = build_opener(proxy_handler)
            install_opener(opener)

        try:
            response = urlopen('https://www.google.com/recaptcha/api/siteverify',
                               data=urlencode(params).encode('utf-8'))
            data = response.read().decode('utf-8')
            response.close()
        except Exception as e:
            logger.error(str(e))
            raise ValidationError(self.errors['nocaptcha-not-reachable'])

        return data

    def __call__(self, form, field):
        # Captcha challenge response is required
        import ipdb; ipdb.set_trace()
        if not field.data:
            raise ValidationError(field.gettext(self.empty_error_text))

        # Construct params assuming all the data is present
        params = (('secret', field.private_key),
                  ('remoteip', field.ip_address),
                  ('response', field.data))

        data = json.loads(self._call_verify(params, field.http_proxy))
        # sample bad response: {'error-codes': ['invalid-input-response', 'missing-input-secret'], 'success': False}
        if not data['success']:
            # Show only incorrect solution to the user else show default message
            error_list = data['error-codes']

            # Log error message in case it wasn't triggered by user
            logger.error('nocaptcha response errors: %s' % str(error_list))

            # put together a string of errors
            error_text = "\n".join(errors[error_code] for error_code in error_list])

            raise ValidationError(field.gettext(error_text))
