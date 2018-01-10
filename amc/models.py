import socket, uuid

from django.db import models, transaction
from django.db.models import fields, signals
from django.dispatch import receiver
from django.utils.encoding import force_text
from django.utils.functional import Promise
from django.utils.translation import ugettext_lazy as _


class AMCFieldMixin(object):
    char_field_max_length = 127

    def __init__(self, *args, **kwargs):
        self.tag_text = kwargs.pop('tag_text', None)
        super(AMCFieldMixin, self).__init__(*args, **kwargs)


class AMCCharField(AMCFieldMixin, fields.CharField):  pass
class AMCBooleanField(AMCFieldMixin, fields.BooleanField): pass
class AMCNullBooleanField(AMCFieldMixin, fields.NullBooleanField): pass
class AMCIntegerField(AMCFieldMixin, fields.IntegerField): pass
class AMCFloatField(AMCFieldMixin, fields.FloatField): pass
class AMCDateField(AMCFieldMixin, fields.DateField): pass
class AMCEmailField(AMCFieldMixin, fields.EmailField): pass
class AMCUUIDField(AMCFieldMixin, fields.UUIDField): pass


class SimplePayload(models.Model):
    class Meta:
        abstract = True


    def _as_pldict(self):
        d = {}
        concrete_model = self._meta.concrete_model
        for field in concrete_model._meta.local_fields:
            if not field.serialize: continue
            if not hasattr(field, 'tag_text') or field.tag_text is None:
                continue

            v = field.value_from_object(self)
            if v is None or len(str(v)) < 1: continue

            # dirty hack: plistlib.dump() will cause
            # TypeError: unsupported type: <class 'uuid.UUID'>
            if isinstance(v, uuid.UUID): v = str(v).upper()
            if isinstance(v, Promise): v = force_text(v)
            d[field.tag_text] = v

        return d


    def _from_pldict(self, pld):
        concrete_model = self._meta.concrete_model
        for (k, v) in pld.items():
            if v is None: continue
            # XXX: linear search
            for field in concrete_model._meta.local_fields:
                if not field.serialize: continue
                if field.tag_text == k:
                    setattr(self, field.name, field.to_python(v))
                    break


    pldict = property(_as_pldict, _from_pldict)


# based on 2017-11-28
# https://developer.apple.com/library/content/featuredarticles/iPhoneConfigurationProfileRef/Introduction/Introduction.html#//apple_ref/doc/uid/TP40010206
"""Assign default value which has choice"""

class Configuration(SimplePayload):
    """Configuration Profile Keys
    At the top level, a profile property list contains the following
    keys:
    """

    class Meta:
        verbose_name = _('Configuration Profile')


    def __init__(self, *args, **kwargs):
        super(Configuration, self).__init__(*args, **kwargs)
        self._payload_contents = []


    def add_payload(self, payload):
        """add PayloadContent

        Array: Optional
        Array of payload dictionaries. Not present if IsEncrypted is true.
        This method is introduced for profile which is not persistent.
        """
        robjs = [c for c in Configuration._meta.related_objects
                 if c.one_to_many]
        found = False
        for robj in robjs:
            if payload.__class__ == robj.related_model:
                found = True
                break
        if not found:
            raise ValueError('not exist in related_objects')

        # more better way?
        s = getattr(self, robj.get_accessor_name())
        if s.filter(payload_identifier=payload.payload_identifier) \
           or any([payload.payload_identifier == p.payload_identifier
                   for p in self._payload_contents]):
            raise ValueError('duplicate PayloadIdentifier')

        self._payload_contents.append(payload)


    def save(self, *args, **kwargs):
        """persist object

        if boolean arg ``with_payloads`` is true, payloads added by
        ``add_payload`` will be also saved.
        """
        with_payloads = kwargs.pop('with_payloads', False)
        super(Configuration, self).save(*args, **kwargs)
        if not with_payloads: return

        with transaction.atomic():
            for payload in self._payload_contents:
                payload.configuration = self
                payload.save(*args, **kwargs)

        self._payload_contents = []


    def _as_pldict(self):
        pld = super(Configuration, self)._as_pldict()
        [self._payload_contents.append(c)
         for robj in Configuration._meta.related_objects
         for c in getattr(self, robj.get_accessor_name()).iterator()]

        if len(self._payload_contents) < 1:
            return pld

        pld['PayloadContent'] = [c._as_pldict() for c in self._payload_contents]
        return pld


    def _from_pldict(self, pld):
        super(Configuration, self)._from_pldict(pld)
        if not 'PayloadContent' in pld:  return

        for content in pld['PayloadContent']:
            payload = PAYLOAD_TYPES[content['PayloadType']]()
            payload._from_pldict(content)
            self._payload_contents.append(payload)

        return self


    pldict = property(_as_pldict, _from_pldict)


    payload_description = AMCCharField(
        tag_text='PayloadDescription',
        verbose_name=_('Description'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "PayloadDescription, String: Optional."
            " A description of the profile, shown on the Detail"
            " screen for the profile. This should be descriptive"
            " enough to help the user decide whether to install the"
            " profile."
        )
    )


    payload_display_name = AMCCharField(
        tag_text='PayloadDisplayName',
        verbose_name=_('Display name'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "PayloadDisplayName, String: Optional."
            " A human-readable name for the profile. This value is"
            " displayed on the Detail screen. It does not have to be"
            " unique."
        )
    )


    payload_expiration_date = AMCDateField(
        tag_text='PayloadExpirationDate',
        verbose_name=_('Expiration date'),
        null=True, blank=True,
        help_text=_(
            "PayloadExpirationDate, Date: Optional."
            " A date on which a profile is considered to have"
            " expired and can be" " updated over the air. This key is"
            " only used if the profile is" " delivered via"
            " over-the-air profile delivery."
        )
    )


    # assign default value - original rule
    payload_identifier = AMCCharField(
        tag_text='PayloadIdentifier',
        verbose_name=_('Identifier'),
        default='.'.join(reversed(socket.getfqdn().split('.'))),
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "PayloadIdentifier, String."
            " A reverse-DNS style identifier"
            " (com.example.myprofile, for example) that identifies"
            " the profile. This string is used to determine whether"
            " a new profile should replace an existing one or"
            " should be added."
        )
    )


    payload_organization = AMCCharField(
        tag_text='PayloadOrganization',
        verbose_name=_('Organization'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "PayloadOrganization, String: Optional"
            " A human-readable string containing the name of the"
            " organization that provided the profile."
        )
    )


    payload_uuid = AMCUUIDField(
        tag_text='PayloadUUID',
        verbose_name=_('UUID'),
        default=uuid.uuid4(),
        editable=False,
        help_text=_(
            "PayloadUUID, String."
            " A globally unique identifier for the profile. The"
            " actual content is unimportant, but it must be globally"
            " unique. In macOS, you can use uuidgen to generate"
            " reasonable UUIDs."
        )
    )


    payload_removal_disallowed = AMCNullBooleanField(
        tag_text='PayloadRemovalDisallowed',
        verbose_name=_('Removal disallowed'),
        null=True, blank=True,
        help_text=_(
            "PayloadRemovalDisallowed, Boolean: Optional."
            " Supervised only. If present and set to true, the user"
            " cannot delete the profile (unless the profile has a"
            " removal password and the user provides it)."
        )
    )


    payload_type = AMCCharField(
        tag_text='PayloadType',
        verbose_name=_('Type'),
        default='Configuration',
        editable=False,
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "PayloadType, String."
            " The only supported value is Configuration."
        )
    )


    payload_version = AMCIntegerField(
        tag_text='PayloadVersion',
        verbose_name=_('Version'),
        default=1,
        editable=False,
        help_text=_(
            "PayloadVersion, Integer."
            " The version number of the profile format. This describes"
            " the version of the configuration profile as a whole, not"
            " of the individual profiles within it. Currently, this"
            " value should be 1."
        )
    )


    payload_scope = AMCCharField(
        tag_text='PayloadScope',
        verbose_name=_('Scope'),
        choices=(('User', 'User'), ('System', 'System')),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "PayloadScope, String: Optional"
            " Determines if the profile should be installed for the"
            " system or the user. In many cases, it determines the"
            " location of the certificate items, such as"
            " keychains. Though it is not possible to declare"
            " different payload scopes, payloads, like VPN, may"
            " automatically install their items in both scopes if"
            " needed. Legal values are System and User, with User as"
            " the default value. Availability: Available in macOS"
            " 10.7 and later."
        )
    )


    removal_date = AMCDateField(
        tag_text='RemovalDate',
        verbose_name=_('Removal date'),
        null=True, blank=True,
        help_text=_(
            "RemovalDate, Date: Optional. "
            " The date on which the profile will be automatically"
            " removed."
        )
    )


    duration_until_removal = AMCFloatField(
        tag_text='DurationUntilRemoval',
        verbose_name=_('Duration until removal'),
        null=True, blank=True,
        help_text=_(
            "DurationUntilRemoval, Float: Optional."
            " Number of seconds until the profile is automatically"
            " removed. If the RemovalDate keys is present, whichever"
            " field yields the earliest date will be used."
        )
    )


    # ConsentText
    # Dictionary: Optional
    # A dictionary containing these keys and values: For each
    # language in which a consent or license agreement is available,
    # a key consisting of the IETF BCP 47 identifier for that
    # language (for example, en or jp) and a value consisting of the
    # agreement localized to that language. The agreement is
    # displayed in a dialog to which the user must agree before
    # installing the profile. The optional key default with its
    # value consisting of the unlocalized agreement (usually in
    # en). The system chooses a localized version in the order of
    # preference specified by the user (macOS) or based on the
    # user’s current language setting (iOS). If no exact match is
    # found, the default localization is used. If there is no
    # default localization, the en localization is used. If there is
    # no en localization, then the first available localization is
    # used. You should provide a default value if possible. No
    # warning will be displayed if the user’s locale does not match
    # any localization in the ConsentText dictionary.


class CommonPayload(SimplePayload):
    """Common part of each payload. i.e. Payload base class.

    If a PayloadContent value is provided in a payload, each entry in the
    array is a dictionary representing a configuration payload. The following
    keys are common to all payloads:
    """
    class Meta:
        abstract = True


    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)

    payload_type = AMCCharField(
        tag_text='PayloadType',
        verbose_name=_('Type'),
        default = _('Unconfigured type'),
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "PayloadType, String."
            " The payload type. The payload types are described in"
            " Payload-Specific Property Keys."
        )
    )


    payload_version = AMCIntegerField(
        tag_text='PayloadVersion',
        verbose_name=_('Version'),
        default=-1,
        help_text=_(
            "PayloadVersion, Integer."
            " The version number of the individual payload.  A profile"
            " can consist of payloads with different version"
            " numbers. For example, changes to the VPN software in iOS"
            " might introduce a new payload version to support"
            " additional features, but Mail payload versions would not"
            " necessarily change in the same release."
        )
    )


    # assign default value - original rule
    payload_identifier = AMCCharField(
        tag_text='PayloadIdentifier',
        verbose_name=_('Identifier'),
        default='.'.join(reversed(socket.getfqdn().split('.'))),
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "PayloadIdentifier, String."
            " A reverse-DNS-style identifier for the specific"
            " payload. It is usually the same identifier as the"
            " root-level PayloadIdentifier value with an additional"
            " component appended."
        )
    )


    payload_uuid = AMCUUIDField(
        tag_text='PayloadUUID',
        verbose_name=_('UUID'),
        default=uuid.uuid4(),
        editable=False,
        help_text=_(
            "PayloadUUID, String."
            " A globally unique identifier for the payload. The actual"
            " content is unimportant, but it must be globally"
            " unique. In macOS, you can use uuidgen to generate"
            " reasonable UUIDs."
        )
    )

    # assign default value - original rule
    payload_display_name = AMCCharField( # not nullable? differ from Configuration
        tag_text='PayloadDisplayName',
        verbose_name=_('Display name'),
        default = _('Unconfigured display name'),
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "PayloadDisplayName, String."
            " A human-readable name for the profile payload. This name"
            " is displayed on the Detail screen. It does not have to"
            " be unique."
        )
    )


    payload_description = AMCCharField(
        tag_text='PayloadDescription',
        verbose_name=_('Description'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "PayloadDescription, String: Optional."
            " A human-readable description of this payload. This"
            " description is shown on the Detail screen."
        )
    )


    payload_organization = AMCCharField(
        tag_text='PayloadOrganization',
        verbose_name=_('Organization'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "PayloadOrganization, String: Optional."
            " A human-readable string containing the name of the"
            " organization that provided the profile.  The payload"
            " organization for a payload need not match the payload"
            " organization in the enclosing profile."
        )
    )

class EmailPayload(CommonPayload):
    """Email payload

    An email payload creates an email account on the device.  In addition to
    the settings common to all payloads, this payload defines the following
    keys:
    """

    class Meta:
        verbose_name = _('Email Payload')


    EMAIL_ACCOUNT_TYPE_CHOICES = (
        ('EmailTypePOP', 'POP'),
        ('EmailTypeIMAP', 'IMAP'),
    )

    INCOMMING_MAIL_SERVER_AUTHENTICATION_CHOICES = (
        ('EmailAuthPassword', 'Password'),
        ('EmailAuthCRAMMD5', 'CRAM MD5'),
        ('EmailAuthNTLM', 'NTLM'),
        ('EmailAuthHTTPMD5', 'HTTP MD5'),
    )

    OUTGOING_MAIL_SERVER_AUTHENTICATION_CHOICES = (
        ('EmailAuthPassword', 'Password'),
        ('EmailAuthCRAMMD5', 'CRAM MD5'),
        ('EmailAuthNTLM', 'NTLM'),
        ('EmailAuthHTTPMD5', 'HTTP MD5'),
        ('EmailAuthNone', 'None'),
    )


    def __init__(self, *args, **kwargs):
        meta = self._meta
        meta.get_field('payload_type').default = 'com.apple.mail.managed'
        meta.get_field('payload_type').editale = False
        meta.get_field('payload_version').default = 1
        meta.get_field('payload_version').editable = False
        super(EmailPayload, self).__init__(*args, **kwargs)


    email_account_description = AMCCharField(
        tag_text='EmailAccountDescription',
        verbose_name=_('Email account description'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "EmailAccountDescription, String: Optional."
            " A user-visible description of the email account, shown"
            " in the Mail and Settings applications."
        )
    )


    email_account_name = AMCCharField(
        tag_text='EmailAccountName',
        verbose_name=_('Email account name'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "EmailAccountName, String: Optional."
            " The full user name for the account. This is the user"
            " name in sent messages, etc."
        )
    )


    # assign default value - original rule
    email_account_type = AMCCharField(
        tag_text='EmailAccountType',
        verbose_name=_('Email account type'),
        choices=EMAIL_ACCOUNT_TYPE_CHOICES,
        default='EmailTypeIMAP',
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "EmailAccountType, String."
            " Allowed values are EmailTypePOP and"
            " EmailTypeIMAP. Defines the protocol to be used for that"
            " account."
        )
    )


    email_address = AMCEmailField(
        tag_text='EmailAddress',
        verbose_name=_('Email address'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "EmailAddress, String."
            " Designates the full email address for the account. If"
            " not present in the payload, the device prompts for this"
            " string during profile installation."
        )
    )


    # assign default value - original rule
    incoming_mail_server_authentication = AMCCharField(
        tag_text='IncomingMailServerAuthentication',
        verbose_name=_('Incoming mail authentication'),
        choices=INCOMMING_MAIL_SERVER_AUTHENTICATION_CHOICES,
        default='EmailAuthPassword', # selfish
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "IncomingMailServerAuthentication, String."
            " Designates the authentication scheme for incoming"
            " mail. Allowed values are EmailAuthPassword,"
            " EmailAuthCRAMMD5, EmailAuthNTLM, EmailAuthHTTPMD5, and"
            " EmailAuthNone."
        )
    )


    incoming_mail_server_host_name = AMCCharField(
        tag_text='IncomingMailServerHostName',
        max_length=AMCFieldMixin.char_field_max_length,
        verbose_name=_('Incoming mail server'),
        help_text=_(
            "IncomingMailServerHostName, String."
            " Designates the incoming mail server host name (or IP"
            " address)."
        )
    )


    incoming_mail_server_port_number = AMCIntegerField(
        tag_text='IncomingMailServerPortNumber',
        verbose_name=_('Incoming mail port'),
        null=True, blank=True,
        help_text=_(
            "IncomingMailServerPortNumber, Integer: Optional."
            " Designates the incoming mail server port number. If no"
            " port number is specified, the default port for a given"
            " protocol is used."
        )
    )

    incoming_mail_server_use_ssl = AMCNullBooleanField(
        tag_text='IncomingMailServerUseSSL',
        verbose_name=_('Incoming SSL'),
        null=True, blank=True,
        help_text=_(
            "IncomingMailServerUseSSL, Boolean: Optional."
            " Default false. Designates whether the incoming mail"
            " server uses SSL for authentication."
        )
    )


    incoming_mail_server_username = AMCCharField(
        tag_text='IncomingMailServerUsername',
        verbose_name=_('Incoming user name'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "IncomingMailServerUsername, String."
            " Designates the user name for the email account, usually"
            " the same as the email address up to the @ character. If"
            " not presentin the payload, and the account is set up to"
            " require authentication for incoming email, the device"
            " will prompt for this string during profile"
            " installation."
        )
    )


    incoming_password = AMCCharField(
        tag_text='IncomingPassword',
        verbose_name=_('Incoming password'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "IncomingPassword, String: Optional."
            " Password for the Incoming Mail Server. Use only with"
            " encrypted profiles."
        )
    )


    outgoing_password = AMCCharField(
        tag_text='OutgoingPassword',
        verbose_name=_('Outgoing password'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "OutgoingPassword,String: Optional."
            " Password for the Outgoing Mail Server. Use only with"
            " encrypted profiles."
        )
    )


    outgoing_password_same_as_incoming_password = AMCNullBooleanField(
        tag_text='OutgoingPasswordSameAsIncomingPassword',
        verbose_name=_('Use incomming password as outgoing'),
        null=True, blank=True,
        help_text=_(
            "OutgoingPasswordSameAsIncomingPassword, Boolean: Optional."
            " If set, the user will be prompted for the password only"
            " once and it will be used for both outgoing and incoming"
            " mail."
        )
    )


    # assign default value - original rule
    outgoing_mail_server_authentication = AMCCharField(
        tag_text='OutgoingMailServerAuthentication',
        verbose_name=_('Outgoing mail authentication'),
        choices=OUTGOING_MAIL_SERVER_AUTHENTICATION_CHOICES,
        default='EmailAuthNone',
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "OutgoingMailServerAuthentication, String."
            " Designates the authentication scheme for outgoing"
            " mail. Allowed values are EmailAuthPassword,"
            " EmailAuthCRAMMD5, EmailAuthNTLM, EmailAuthHTTPMD5, and"
            " EmailAuthNone."
        )
     )


    outgoing_mail_server_host_name = AMCCharField(
        tag_text='OutgoingMailServerHostName',
        verbose_name=_('Outgoing mail server'),
        max_length=AMCFieldMixin.char_field_max_length,
        help_text=_(
            "OutgoingMailServerHostName, String."
            "Designates the outgoing mail server host name (or IP"
            " address)."
        )
     )


    outgoing_mail_server_port_number = AMCIntegerField(
        tag_text='OutgoingMailServerPortNumber',
        verbose_name=_('Outgoing mail port'),
        null=True, blank=True,
        help_text=_(
            "OutgoingMailServerPortNumber, Integer: Optional."
            " Designates the outgoing mail server port number. If no"
            " port number is specified, ports 25, 587 and 465 are"
            " used, in this order."
        )
    )


    outgoing_mail_server_use_ssl = AMCNullBooleanField(
        tag_text='OutgoingMailServerUseSSL',
        verbose_name=_('Use SSL on outgoing'),
        null=True, blank=True,
        help_text=_(
            "OutgoingMailServerUseSSL, Boolean: Optional."
            " Default false. Designates whether the outgoing mail"
            " server uses SSL for authentication."
        )
    )


    outgoing_mail_server_username = AMCCharField(
        tag_text='OutgoingMailServerUsername',
        verbose_name=_('Outgoing mail user name'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "OutgoingMailServerUsername, String."
            " Designates the user name for the email account, usually"
            " the same as the email address up to the @ character. If"
            " not present in the payload, and the account is set up to"
            " require authentication for outgoing email, the device"
            " prompts for this string during profile installation."
        )
    )


    prevent_move = AMCNullBooleanField(
        tag_text='PreventMove',
        verbose_name=_('Prevent move'),
        null=True, blank=True,
        help_text=_(
            "PreventMove, Boolean: Optional. "
            " Default false.  If true, messages may not be moved out"
            " of this email account into another account. Also"
            " prevents forwarding or replying from a different account"
            " than the message was originated from.  Availability:"
            " Available only in iOS 5.0 and later."
        )
    )


    prevent_app_sheet = AMCNullBooleanField(
        tag_text='PreventAppSheet',
        verbose_name=_('Prevent app sheet'),
        null=True, blank=True,
        help_text=_(
            "PreventAppSheet, Boolean: Optional."
            " Default false. If true, this account is not available"
            " for sending mail in any app other than the Apple Mail"
            " app. Availability: Available only in iOS 5.0 and"
            " later."
        )
    )


    smime_enabled = AMCNullBooleanField(
        tag_text='SMIMEEnabled',
        verbose_name=_('S/MIME enable'),
        null=True, blank=True,
        help_text=_(
            "SMIMEEnabled, Boolean: Optional."
            " Default false. If true, this account supports S/MIME. As"
            " of iOS 10.0, this key is ignored. Availability:"
            " Available only in iOS 5.0 through iOS 9.3.3."
        )
    )


    smime_signing_enabled = AMCNullBooleanField(
        tag_text='SMIMESigningEnabled',
        verbose_name=_('S/MIME sign enable'),
        null=True, blank=True,
        help_text=_(
            "SMIMESigningEnabled, Boolean: Optional."
            " Default true. If set to true, S/MIME signing is enabled"
            " for this account. Availability: Available only in iOS"
            " 10.3 and later."
        )
    )

    # should use UUID?
    smime_signing_certificate_uuid = AMCCharField(
        tag_text='SMIMESigningCertificateUUID',
        verbose_name=_('S/MIME sign certificate UUID'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "SMIMESigningCertificateUUID, String: Optional."
            " The PayloadUUID of the identity certificate used to sign"
            " messages sent from this account. Availability: Available"
            " only in iOS 5.0 and later."
        )
    )


    smime_encryption_enabled = AMCNullBooleanField(
        tag_text='SMIMEEncryptionEnabled',
        verbose_name=_('S/MIME encryption enabled'),
        blank=True,
        help_text=_(
            "SMIMEEncryptionEnabled, Boolean: Optional."
            " Default false. If set to true, S/MIME encryption is on"
            " by default for this account. Availability: Available"
            " only in iOS 10.3 and later."
        )
    )


    # should use UUID?
    smime_encryption_certificate_uuid = AMCCharField(
        tag_text='SMIMEEncryptionCertificateUUID',
        verbose_name=_('S/MIME encryption certificate UUID'),
        max_length=AMCFieldMixin.char_field_max_length,
        blank=True,
        help_text=_(
            "SMIMEEncryptionCertificateUUID, String: Optional."
            " The PayloadUUID of the identity certificate used to"
            " decrypt messages sent to this account. The public"
            " certificate is attached to outgoing mail to allow"
            " encrypted mail to be sent to this user. When the user"
            " sends encrypted mail, the public certificate is used to"
            " encrypt the copy of the mail in their Sent"
            " mailbox. Availability: Available only in iOS 5.0 and"
            " later."
        )
    )


    smime_enable_per_message_switch = AMCNullBooleanField(
        tag_text='SMIMEEnablePerMessageSwitch',
        verbose_name=_('S/MIME per message switch enable'),
        null=True, blank=True,
        help_text=_(
            "SMIMEEnablePerMessageSwitch, Boolean: Optional."
            " Default false. If set to true, displays the per-message"
            " encryption switch in the Mail Compose UI. Availability:"
            " Available only in iOS 8.0 and later."
        )
    )


    # default is specified but required?
    disable_mail_recents_syncing = AMCBooleanField(
        tag_text='disableMailRecentsSyncing',
        verbose_name=_('Disable recents address syncing'),
        default=False,
        help_text=_(
            "disableMailRecentsSyncing, Boolean."
            " If true, this account is excluded from address Recents"
            " syncing. This defaults to false. Availability: Available"
            " only in iOS 6.0 and later."
        )
    )


    allow_mail_drop = AMCNullBooleanField(
        tag_text='allowMailDrop',
        verbose_name=_('Allow mail drop'),
        null=True, blank=True,
        help_text=_(
            "allowMailDrop, Boolean: Optional."
            " If true, this account is allowed to use Mail Drop. The"
            " default is false. Availability: Available in iOS 9.2 and"
            " later."
        )
    )


PAYLOAD_TYPES = {
    'com.apple.mail.managed': EmailPayload,
}
