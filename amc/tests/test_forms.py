import uuid, itertools
from django.test import TestCase
from .. import forms, models

class ConfigrationFormTests(TestCase):
    def test_initial_value(self):
        """values for non-args constructor
        """
        form = forms.ConfigurationForm()
        self.assertIsNone(form['payload_description'].initial,
                          'initial PayloadDescription is None')
        self.assertIsNone(form['payload_display_name'].initial,
                          'initial PayloadDisplayName is None')
        self.assertIsNone(form['payload_expiration_date'].initial,
                          'initial PayloadExpirationDate is None')
        # reversed FQDN of current host
        self.assertIsNotNone(form['payload_identifier'].initial,
                             'initial PayloadIdentifier is not None')
        self.assertIsNone(form['payload_organization'].initial,
                          'initial PayloadOrganization is None')
        self.assertFalse('payload_uuid' in form,
                         'PayloadUUID is not included')
        self.assertFalse(form['payload_removal_disallowed'].initial,
                         'initial PayloadRemovalDisallowed is False')
        self.assertFalse('payload_type' in form,
                         'initial PayloadType is not included')
        self.assertFalse('payload_version' in form,
                         'initial PayloadVersion is not included')
        self.assertIsNone(form['payload_scope'].initial,
                          'initial PayloadScope is None')
        self.assertIsNone(form['removal_date'].initial,
                          'initial RemovalDate is None')
        self.assertIsNone(form['duration_until_removal'].initial,
                          'initial DurationUntilRemoval is None')
        # no ConsentText - sry I do not understand it ;-)


    def test_minimum_value(self):
        """minimum value for ConfigurationForm
        """
        form = forms.ConfigurationForm({})
        self.assertFalse(form.is_valid(),
                         'ConfigurationForm with empty data is not valid')

        # re-create to clear status
        form = forms.ConfigurationForm({})
        form.data['payload_identifier'] = form['payload_identifier'].initial
        self.assertTrue(form.is_valid(),
                        'is valid only assign `payload_identifier`')

        d = [k for k, v in form.cleaned_data.items()
             if v is not None and len(v) > 0]
        self.assertEqual(len(d), 1,
                         'minimam required key is 1')
        self.assertTrue('payload_identifier' in d,
                        'payload_identifier exists in the key')


    def test_exclude_value(self):
        """should be tested only in models?"""
        form = forms.ConfigurationForm()
        self.assertIsInstance(form.instance.payload_uuid, uuid.UUID,
                              'PayloadUUID is an instance of UUID')
        self.assertEqual(form.instance.payload_type, 'Configuration',
                         'PayloadType is `Configuration`')
        self.assertEqual(form.instance.payload_version, 1,
                         'PayloadVersion is 1')


    def test_save_commit_false(self):
        form = forms.ConfigurationForm()
        model = form.save(commit=False)
        self.assertIsInstance(model, models.Configuration,
                              'is an Configuration instance after save')
        self.assertIsInstance(model.payload_uuid, uuid.UUID,
                              'PayloadUUID is an instance of UUID')
        self.assertEqual(model.payload_type, 'Configuration',
                         'PayloadType is `Configuration`')
        self.assertEqual(model.payload_version, 1,
                         'PayloadVersion is 1')


class EmailPayloadFormTests(TestCase):
    def test_initial_value(self):
        """values for non-args constructor
        """
        form = forms.EmailPayloadForm()

        # Common
        self.assertFalse('payload_type' in form,
                         'PayloadType is not included')
        self.assertFalse('payload_version' in form,
                         'PayloadVersion is not included')
        # reversed FQDN of current host
        self.assertIsNotNone(form['payload_identifier'].initial,
                             'initial PayloadIdentifier is not None')
        self.assertFalse('payload_uuid' in form,
                         'PayloadUUID is not included')
        # Global one is optional but this one is...?
        self.assertIsNotNone(form['payload_display_name'].initial,
                             'initial PayloadDisplayName is not None')
        self.assertIsNone(form['payload_description'].initial,
                          'initial PayloadDescription is None')
        self.assertIsNone(form['payload_organization'].initial,
                          'initial PayloadOrganization is None')

        # EmailPayload Specific
        self.assertIsNone(form['email_account_description'].initial,
                          'initial EmailAccountDescription is None')
        self.assertIsNone(form['email_account_name'].initial,
                          'initial EmailAccountName is None')
        self.assertIsNotNone(form['email_account_type'].initial,
                             'initial EmailAccountType is not None')
        self.assertIsNone(form['email_address'].initial,
                          'initial EmailAddress is None')
        self.assertIsNotNone(form['incoming_mail_server_authentication'].initial,
                             'initial IncomingMailServerAuthentication is not None')
        self.assertIsNone(form['incoming_mail_server_host_name'].initial,
                          'initial IncomingMailServerHostName is None')
        self.assertIsNone(form['incoming_mail_server_port_number'].initial,
                          'initial IncomingMailServerPortNumber is None')
        self.assertIsNone(form['incoming_mail_server_use_ssl'].initial,
                          'initial IncomingMailServerUseSSL is None')
        self.assertIsNone(form['incoming_mail_server_username'].initial,
                          'initial IncomingMailServerUsername is None')
        self.assertIsNone(form['incoming_password'].initial,
                          'initial IncomingPassword is None')
        self.assertIsNone(form['outgoing_password'].initial,
                          'initial OutgoingPassword is None')
        self.assertIsNone(form['outgoing_password_same_as_incoming_password'].initial,
                          'initial OutgoingPasswordSameAsIncomingPassword is None')
        self.assertIsNotNone(form['outgoing_mail_server_authentication'].initial,
                             'initial OutgoingMailServerAuthentication is not None')
        self.assertIsNone(form['outgoing_mail_server_host_name'].initial,
                          'initial OutgoingMailServerHostName is None')
        self.assertIsNone(form['outgoing_mail_server_port_number'].initial,
                          'initial OutgoingMailServerPortNumber is None')
        self.assertIsNone(form['outgoing_mail_server_use_ssl'].initial,
                          'initial OutgoingMailServerUseSSL is None')
        self.assertIsNone(form['outgoing_mail_server_username'].initial,
                          'initial OutgoingMailServerUsername is None')
        self.assertIsNone(form['prevent_move'].initial,
                          'initial PreventMove is None')
        self.assertIsNone(form['prevent_app_sheet'].initial,
                          'initial PreventAppSheet is None')
        self.assertIsNone(form['smime_enabled'].initial,
                          'initial SMIMEEnabled is None')
        self.assertIsNone(form['smime_signing_enabled'].initial,
                          'initial SMIMESigningEnabled is None')
        self.assertIsNone(form['smime_signing_certificate_uuid'].initial,
                          'initial SMIMESigningCertificateUUID is None')
        self.assertIsNone(form['smime_encryption_enabled'].initial,
                          'initial SMIMEEncryptionEnabled is None')
        self.assertIsNone(form['smime_encryption_certificate_uuid'].initial,
                          'initial SMIMEEncryptionCertificateUUID is None')
        self.assertIsNone(form['smime_enable_per_message_switch'].initial,
                          'initial SMIMEEnablePerMessageSwitch is None')
        self.assertFalse(form['disable_mail_recents_syncing'].initial,
                         'initial disableMailRecentsSyncing is False...?')
        self.assertIsNone(form['allow_mail_drop'].initial,
                          'initial allowMailDrop is None')


    def test_minimum_value(self):
        """minimum value for ConfigurationForm
        """
        form = forms.EmailPayloadForm({})
        self.assertFalse(form.is_valid(),
                         'EmailPayloadForm with empty data is not valid')

        # required fields:
        #   PayloadIdentifier
        #   PayloadDisplayName
        #   EmailAccountType
        #   -- EmailAddress # not optional but `the device prompts for this`
        #   IncomingMailServerAuthentication
        #   IncomingMailServerHostName
        #   -- IncomingMailServerUsername # not optional but `the device prompts for this`
        #   OutgoingMailServerAuthentication
        #   --- OutgoingMailServerHostName
        #   OutgoingMailServerUsername # not optional but `the device prompts for this`
        #   ??? disableMailRecentsSyncing
        #     required but this has default value
        #     and default= of BooleanField set initial value as real value?
        data = {
            'payload_identifier': 'payload_identifier',
            'payload_display_name': 'payload_display_name',
            'email_account_type': 'EmailTypeIMAP',
            'incoming_mail_server_authentication': 'EmailAuthPassword',
            'incoming_mail_server_host_name': 'incoming_mail_server_host_name',
            'outgoing_mail_server_authentication': 'EmailAuthPassword',
            'outgoing_mail_server_host_name': 'outgoing_mail_server_host_name',
            # 'disable_mail_recents_syncing': False,
        }

        form = forms.EmailPayloadForm({})
        self.assertFalse(form.is_valid(),
                         'EmailPayloadForm with empty data is not valid')

        for i in range(1, len(data)):
            for c in itertools.combinations(data, i):
                form = forms.EmailPayloadForm({k: data[k] for k in c})
                self.assertFalse(form.is_valid(),
                                 'not valid in case of lacking required value')
                self.assertEqual(len(form.errors), len(data) - i,
                                 'length of errors is %d' % (len(data) - i,))

        form = forms.EmailPayloadForm(data)
        self.assertTrue(form.is_valid(),
                        'is valid on all required value is assigined')


    def test_exclude_value(self):
        """should be tested only in models?"""
        form = forms.EmailPayloadForm()
        self.assertIsInstance(form.instance.payload_uuid, uuid.UUID,
                              'PayloadUUID is an instance of UUID')
        self.assertEqual(form.instance.payload_type, 'com.apple.mail.managed',
                         'PayloadType is `com.apple.mail.managed`')
        self.assertEqual(form.instance.payload_version, 1,
                         'PayloadVersion is 1')


    def test_save_commit_false(self):
        form = forms.EmailPayloadForm()
        model = form.save(commit=False)
        self.assertIsInstance(model, models.EmailPayload,
                              'is an EmailPayload instance after save')
        self.assertIsInstance(model.payload_uuid, uuid.UUID,
                              'PayloadUUID is an instance of UUID')
        self.assertEqual(model.payload_type, 'com.apple.mail.managed',
                         'PayloadType is `com.apple.mail.managed`')
        self.assertEqual(model.payload_version, 1,
                         'PayloadVersion is 1')

        configuration_form = forms.ConfigurationForm()
        configuration_form.add_payload(form)
        configuration_model = configuration_form.save(commit=False)
        self.assertRaises(ValueError, configuration_model.add_payload, model)
        # 'could not add duplicated payload identifier payload'


    def test_save_with_payloads(self):
        form = forms.EmailPayloadForm()
        model = form.save(commit=False)
        self.assertIsInstance(model, models.EmailPayload,
                              'is an EmailPayload instance after save')
        self.assertIsInstance(model.payload_uuid, uuid.UUID,
                              'PayloadUUID is an instance of UUID')
        self.assertEqual(model.payload_type, 'com.apple.mail.managed',
                         'PayloadType is `com.apple.mail.managed`')
        self.assertEqual(model.payload_version, 1,
                         'PayloadVersion is 1')

        configuration_form = forms.ConfigurationForm({
            'payload_identifier': form['payload_identifier'].initial
        })
        configuration_form.add_payload(form)

        configuration_model = configuration_form.save(commit=False)
        self.assertRaises(ValueError, configuration_model.add_payload, model)
        # 'could not add duplicated payload identifier payload'

        try: configuration_model.save(with_payloads=True)
        except Exception as e:
            self.fail('configuration model accepts with_payload arg: %s' % e)
        self.assertRaises(ValueError, configuration_model.add_payload, model)
        # 'could not add duplicated payload identifier payload'
