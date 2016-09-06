import logging
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
        'invalid-site-public-key': u'Invalid public key',
        'invalid-site-private-key': u'Invalid private key',
        'invalid-request-cookie': u'Challenge is incorrect',
        'incorrect-captcha-sol': u'Incorrect captcha solution',
        'verify-params-incorrect': u'Incorrect parameters',
        'invalid-referrer': u'Incorrect domain',
        'recaptcha-not-reachable': u'Could not connect to reCaptcha'
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
            data = response.read().decode('utf-8').splitlines()
            response.close()
        except Exception as e:
            logger.error(str(e))
            raise ValidationError(self.errors['recaptcha-not-reachable'])

        return data

    def __call__(self, form, field):
        # Captcha challenge response is required
        import ipdb; ipdb.set_trace()
        if not field.data:
            raise ValidationError(field.gettext(self.empty_error_text))

        # Construct params assuming all the data is present
        params = (('privatekey', field.private_key),
                  ('remoteip', field.ip_address),
                  ('challenge', field.challenge),
                  ('response', field.data))

        data = self._call_verify(params, field.http_proxy)
        if data[0] == 'false':
            # Show only incorrect solution to the user else show default message
            if data[1] == 'incorrect-captcha-sol':
                raise ValidationError(field.gettext(self.errors[data[1]]))
            else:
                # Log error message in case it wasn't triggered by user
                logger.error(self.errors.get(data[1], data[1]))
                raise ValidationError(field.gettext(self.internal_error_text))
