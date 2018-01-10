django-amc
==========

django-amc is a breaking down [Apple Configuration
Profile](https://developer.apple.com/library/content/featuredarticles/iPhoneConfigurationProfileRef/Introduction/Introduction.html)
into Django model. This currently has only Email Payload.
Description of each elements is cited from Apple web site above.


Quick start
-----------

This does not intendet to be a standalone application, but you can
test it by:

1. Add "amc" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
	...
	'amc.apps.AmcConfig',
    ]

2. Include the amc URLconf in your project urls.py like this::

    from django.conf.urls import include
    url(r'^amc/', include('amc.urls')),

3. Run `python manage.py migrate` to create the amc models.

4. Start the development server by `python manage.py runserver`

5. Visit http://127.0.0.1:8000/amc/ to participate in the amc.
