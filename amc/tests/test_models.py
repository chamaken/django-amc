import uuid, itertools
from django.core import exceptions
from django.test import TestCase
from .. import models


class ConfigurationTests(TestCase):
    def test_empty_construct(self):
        model = models.Configuration()
        try: model.full_clean()
        except Exception as e:
            self.fail('object created with no arg is valid: %s' % e)


    def test_pldict(self):
        model = models.Configuration()

        try: pldict = model.pldict
        except Exception as e:
            self.fail('empty configuration can be a pldict: %s' % e)

        pid = 'Updated.PayloadIdentifier'
        pldict['PayloadIdentifier'] = pid

        try: model.pldict = pldict
        except Exception as e:
            self.fail('dumped and updated pldict is acceptable: %s' % e)

        self.assertEqual(model.payload_identifier, pid,
                         'newly assigned PayloadIdentifier is equal')
        


class EmailPayloadTests(TestCase):
    def test_empty_construct(self):
        model = models.EmailPayload()
        try: model.full_clean()
        except exceptions.ValidationError as e:
            d = e.error_dict
            self.assertEqual(len(d), 3,
                             'empty constructor lacks 2 required fields')
            self.assertIn('incoming_mail_server_host_name', d,
                          'incoming_mail_server_host_name exists in the error')
            self.assertEqual(len(d['incoming_mail_server_host_name']), 1,
                             'incoming_mail_server_host_name has one error')
            self.assertIn('outgoing_mail_server_host_name', d,
                          'outgoing_mail_server_host_name exists in the error')
            self.assertEqual(len(d['outgoing_mail_server_host_name']), 1,
                             'outgoing_mail_server_host_name has one error')
            self.assertIn('configuration', d,
                          'configuration exists in the error')
            self.assertEqual(len(d['configuration']), 1,
                             'configuration has one error')
        else:
            fail('empty constructor is not valid')


    def test_minimum_construct(self):
        configuration = models.Configuration()
        configuration.save()
        model = models.EmailPayload(
            configuration=configuration,
            incoming_mail_server_host_name='incoming_mail_server_host_name',
            outgoing_mail_server_host_name='outgoing_mail_server_host_name',
        )
        try: model.full_clean()
        except Exception as e:
            self.fail('object created with minimum (2) args is valid: %s' % e)


    def test_save_separately(self):
        configuration = models.Configuration()
        try: configuration.save()
        except Exception as e:
            self.fail('empty configuration can save: %s' % e)

        email_payload = models.EmailPayload(
            configuration=configuration,
            incoming_mail_server_host_name='incoming_mail_server_host_name',
            outgoing_mail_server_host_name='outgoing_mail_server_host_name',
        )
        try: email_payload.save()
        except Exception as e:
            self.fail('minimum email payload can save: %s' % e)
        
        payloads = configuration.emailpayload_set.all()
        self.assertEqual(len(payloads), 1,
                         'length of email payload is 1')
        self.assertEqual(payloads[0].id, email_payload.id,
                         'id is equals added just before save')
        self.assertRaises(ValueError, configuration.add_payload, email_payload)
        # 'could not add duplicated payload identifier payload'


    def test_save_with_payloads(self):
        configuration = models.Configuration()
        email_payload = models.EmailPayload(
            incoming_mail_server_host_name='incoming_mail_server_host_name',
            outgoing_mail_server_host_name='outgoing_mail_server_host_name',
        )
        
        try: configuration.save(with_payloads=True)
        except Exception as e:
            self.fail(('empty configuration can save by save_with_payloads'
                       ': %s') % e)
            
        configuration.add_payload(email_payload)
        self.assertRaises(ValueError, configuration.add_payload, email_payload)
        # 'could not add duplicated payload identifier payload'

        try: configuration.save(with_payloads=True)
        except Exception as e:
            self.fail(('configuration has one email payload can save by'
                       'save_with_payloads: %s') % e)

        payloads = configuration.emailpayload_set.all()
        self.assertEqual(len(payloads), 1,
                          'length of email payload is 1')
        self.assertEqual(payloads[0].id, email_payload.id,
                          'id is equals added just before save')

        self.assertRaises(ValueError, configuration.add_payload, email_payload)
        # 'could not add duplicated payload identifier payload'
