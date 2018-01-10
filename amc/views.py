import plistlib

from django.shortcuts import render
from django.http import HttpResponse

from . import forms

def index(request):
    return render(request, 'amc/index.html', {
        'configuration_form': forms.ConfigurationForm(prefix='configuration'),
        'email_payload_form': forms.EmailPayloadForm(prefix='emailpayload'),
    })


def publish(request):
    configuration = forms.ConfigurationForm(request.POST, prefix='configuration')
    email_payload = forms.EmailPayloadForm(request.POST, prefix='emailpayload')

    if not configuration.is_valid() or not email_payload.is_valid():
        return render(request, 'amc/index.html', {
            'configuration_form': configuration,
            'email_payload_form': email_payload,
        })

    configuration.add_payload(email_payload)

    response = HttpResponse(
        plistlib.dumps(configuration.pldict),
        content_type='application/x-apple-aspen-config')
    response['Content-Disposition'] = (
        'attachment; filename="email_profile.mobileconfig"')
    return response
