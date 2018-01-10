from django import forms

from . import models

class ACMModelForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(ACMModelForm, self).__init__(*args, **kwargs)
        for _, field in self.fields.items():
            attrs = field.widget.attrs
            attrs.update({
                'class': attrs.get('class', '') + ' form-control',
            })

    @property
    def verbose_name(self):
        return self._meta.model._meta.verbose_name


    def _get_pldict(self): return self.instance.pldict
    def _set_pldict(self, pld): self.instance.pldict = pld
    pldict = property(_get_pldict, _set_pldict)


class ConfigurationForm(ACMModelForm):
    """A Form based on models.Configuration

    this does not have with_payloads args for save() since it will
    be a copy of django.forms.models. Then you need to do like:

      model = form.save(commit=False)
      model.save(with_payloads=True)

    or should I implement save(with_payloads) even if a copy?
    """
    class Meta:
        model = models.Configuration
        fields = [ # apple document order
            'payload_description',
            'payload_display_name',
            'payload_expiration_date',
            'payload_identifier',
            'payload_organization',
            # 'payload_uuid',
            'payload_removal_disallowed',
            # 'payload_type',
            # 'payload_version',
            'payload_scope',
            'removal_date',
            'duration_until_removal',
        ]


    def add_payload(self, payload):
        self.instance.add_payload(payload.instance)


class EmailPayloadForm(ACMModelForm):
    class Meta:
        model = models.EmailPayload
        fields = [ # apple document order
            # Common to All Payloads
            # 'payload_type',
            # 'payload_version',
            'payload_identifier',
            # 'payload_uuid',
            'payload_display_name',
            'payload_description',
            'payload_organization',

            # Email Payload
            # 'configuration',
            'email_account_description',
            'email_account_name',
            'email_account_type',
            'email_address',
            'incoming_mail_server_authentication',
            'incoming_mail_server_host_name',
            'incoming_mail_server_port_number',
            'incoming_mail_server_use_ssl',
            'incoming_mail_server_username',
            'incoming_password',
            'outgoing_password',
            'outgoing_password_same_as_incoming_password',
            'outgoing_mail_server_authentication',
            'outgoing_mail_server_host_name',
            'outgoing_mail_server_port_number',
            'outgoing_mail_server_use_ssl',
            'outgoing_mail_server_username',
            'prevent_move',
            'prevent_app_sheet',
            'smime_enabled',
            'smime_signing_enabled',
            'smime_signing_certificate_uuid',
            'smime_encryption_enabled',
            'smime_encryption_certificate_uuid',
            'smime_enable_per_message_switch',
            'disable_mail_recents_syncing',
            'allow_mail_drop',
        ]


    def __init__(self, *args, **kwargs):
        super(EmailPayloadForm, self).__init__(*args, **kwargs)
        # https://docs.djangoproject.com/en/2.0/ref/forms/fields/#booleanfield
        self.fields['disable_mail_recents_syncing'].required = False


# We can define by using ModelForm but extend normal Form and take annoying way
# for thought of combining with multiple - Configuration and EmailPayload models
class AMCFieldMixin(object):
    def __init__(self, *args, **kwargs):
        if 'model_class' in kwargs and 'model_field' in kwargs:
            model_class = kwargs.pop('model_class')
            model_field = kwargs.pop('model_field')
            if not 'max_length' in kwargs:
                kwargs['max_length'] = [f.max_length
                                        for f in model_class._meta.fields
                                        if f.name == model_field][0]
            if not 'label' in kwargs:
                kwargs['label'] = [f.verbose_name
                                   for f in model_class._meta.fields
                                   if f.name == model_field][0]

            if not 'help_text' in kwargs:
                kwargs['help_text'] = [f.help_text
                                       for f in model_class._meta.fields
                                       if f.name == model_field][0]

        super(AMCFieldMixin, self).__init__(*args, **kwargs)

        self.widget.attrs.update({
            'class': self.widget.attrs.get('class', '') + ' form-control',
        })


class AMCCharField(AMCFieldMixin, forms.CharField): pass
class AMCEmailField(AMCFieldMixin, forms.EmailField): pass
