from wtforms.widgets import HTMLString

# Template for the widget
NOCAPTCHA_HTML = HTMLString("""
<script type="text/javascript"
 src="%(protocol)s://www.google.com/recaptcha/api.js?hl=en">
</script>
<div class="g-recaptcha" data-sitekey="%(public_key)s">
</div>
""")


class NoCaptcha(object):
    """No Captcha widget that displays HTML depending on security status"""

    def __call__(self, field, **kwargs):
        html = NOCAPTCHA_HTML % {
                'protocol': field.secure and 'https' or 'http',
                'public_key': field.public_key
        }
        return html
