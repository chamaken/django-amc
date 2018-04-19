import socket, uuid

from django.db import models, transaction
from django.db.models import fields, signals
from django.dispatch import receiver
from django.utils.encoding import force_text
from django.utils.functional import Promise
from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe


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
        return self


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
         if robj.one_to_many
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


    configuration = models.ForeignKey(
        Configuration,
        blank=True, null=True,
        on_delete=models.CASCADE)


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


class RestrictionsPayload(CommonPayload):
    """Restrictions Payload

    A Restrictions payload allows the administrator to restrict the user from
    doing certain things with the device, such as using the camera.

    Note: You can specify additional restrictions, including maximum allowed
    content ratings, by creating a profile using Apple Configurator 2 or Profile
    Manager.
    """

    class Meta:
        verbose_name = _('Restrictions Payload')


    def __init__(self, *args, **kwargs):
        meta = self._meta
        meta.get_field('payload_type').default = 'com.apple.applicationaccess'
        meta.get_field('payload_type').editale = False
        meta.get_field('payload_version').default = 1
        meta.get_field('payload_version').editable = False
        super(RestrictionsPayload, self).__init__(*args, **kwargs)


    allow_account_modification = AMCNullBooleanField(
        tag_text='allowAccountModification',
        verbose_name=_('Allow Account Modification'),
        null=True, blank=True,
        help_text=_(
            "allowAccountModification, Boolean: Optional."
            " Supervised only. If set to false, account modification is"
            " disabled. Availability: Available only in iOS 7.0 and"
            " later."
        )
    )


    allow_adding_game_center_friends = AMCNullBooleanField(
        tag_text='allowAddingGameCenterFriends',
        verbose_name=_('Allow Adding Game Center Friends'),
        null=True, blank=True,
        help_text=_(
            "allowAddingGameCenterFriends, Boolean: Optional. When"
            " false, prohibits adding friends to Game Center. This"
            " key is deprecated on unsupervised devices."
        )
    )


    allow_air_drop = AMCNullBooleanField(
        tag_text='allowAirDrop',
        verbose_name=_('Allow Air Drop'),
        null=True, blank=True,
        help_text=_(
            "allowAirDrop, Boolean: Optional. Supervised only. If set to"
            " false, AirDrop is disabled. Availability: Available only"
            " in iOS 7.0 and later."
        )
    )


    allow_app_cellular_data_modification = AMCNullBooleanField(
        tag_text='allowAppCellularDataModification',
        verbose_name=_('Allow App Cellular Data Modification'),
        null=True, blank=True,
        help_text=_(
            "allowAppCellularDataModification, Boolean: Optional."
            " Supervised only. If set to false, changes to cellular data"
            " usage for apps are disabled. Availability: Available only"
            " in iOS 7.0 and later."
        )
    )


    allow_app_installation = AMCNullBooleanField(
        tag_text='allowAppInstallation',
        verbose_name=_('Allow App Installation'),
        null=True, blank=True,
        help_text=_(
            "allowAppInstallation, Boolean: Optional. Supervised"
            " only. When false, the App Store is disabled and its icon"
            " is removed from the Home screen. Users are unable to "
            " install or update their applications. This key is"
            " deprecated on unsupervised devices."
        )
    )


    allow_app_removal = AMCNullBooleanField(
        tag_text='allowAppRemoval',
        verbose_name=_('Allow App Removal'),
        null=True, blank=True,
        help_text=_(
            "allowAppRemoval, Boolean: Optional. When false, disables"
            "removal of apps from iOS device. This key is deprecated on"
            " unsupervised devices."
        )
    )


    allow_assistant = AMCNullBooleanField(
        tag_text='allowAssistant',
        verbose_name=_('Allow Assistant'),
        null=True, blank=True,
        help_text=_(
            "allowAssistant, Boolean: Optional. When false, disables"
            " Siri. Defaults to true."
        )
    )


    allow_assistant_user_generated_content = AMCNullBooleanField(
        tag_text='allowAssistantUserGeneratedContent',
        verbose_name=_('Allow Assistant User Generated Content'),
        null=True, blank=True,
        help_text=_(
            "allowAssistantUserGeneratedContent, Boolean: Optional."
            " Supervised only. When false, prevents Siri from querying"
            " user-generated content from the web.  Availability:"
            " Available in iOS 7 and later."
        )
    )

    allow_assistant_while_locked = AMCNullBooleanField(
        tag_text='allowAssistantWhileLocked',
        verbose_name=_('Allow Assistant While Locked'),
        null=True, blank=True,
        help_text=_(
            "allowAssistantWhileLocked, Boolean: Optional. When false,"
            " the user is unable to use Siri when the device is"
            " locked. Defaults to true. This restriction is ignored if"
            " the device does not have a passcode set. Availability:"
            " Available only in iOS 5.1 and later."
        )
    )


    allow_bookstore = AMCNullBooleanField(
        tag_text='allowBookstore',
        verbose_name=_('Allow Bookstore'),
        null=True, blank=True,
        help_text=_(
            "allowBookstore, Boolean: Optional. Supervised only. If set"
            " to false, the iBooks Store will be disabled. This will"
            " default to true.  Availability: Available in iOS 6.0 and"
            " later."
        )
    )


    allow_bookstore_erotica = AMCNullBooleanField(
        tag_text='allowBookstoreErotica',
        verbose_name=_('Allow Bookstore Erotica'),
        null=True, blank=True,
        help_text=_(
            " allowBookstoreErotica, Boolean: Optional. Supervised only"
            " prior to iOS 6.1. If set to false, the user will not be"
            " able to download media from the iBooks Store that has been"
            " tagged as erotica. This will default to true."
            " Availability: Available in iOS and in tvOS 11.3 and later."
        )
    )


    allow_camera = AMCNullBooleanField(
        tag_text='allowCamera',
        verbose_name=_('Allow Camera'),
        null=True, blank=True,
        help_text=_(
            "allowCamera, Boolean: Optional. When false, the camera is"
            " completely disabled and its icon is removed from the Home"
            " screen. Users are unable to take photographs."
            " Availability: Available in iOS and in macOS 10.11 and "
            " later."
        )
    )


    allow_chat = AMCNullBooleanField(
        tag_text='allowChat',
        verbose_name=_('Allow Chat'),
        null=True, blank=True,
        help_text=_(
            "allowChat, Boolean: Optional. When false, disables the use"
            " of the Messages app with supervised devices. Availability:"
            " Available in iOS 6.0 and later."
        )
    )


    allow_cloud_backup = AMCNullBooleanField(
        tag_text='allowCloudBackup',
        verbose_name=_('Allow Cloud Backup'),
        null=True, blank=True,
        help_text=_(
            "allowCloudBackup, Boolean: Optional. When false, disables"
            " backing up the device to iCloud.  Availability: Available"
            " in iOS 5.0 and later."
        )
    )


    allow_cloud_bookmarks = AMCNullBooleanField(
        tag_text='allowCloudBookmarks',
        verbose_name=_('Allow Cloud Bookmarks'),
        null=True, blank=True,
        help_text=_(
            "allowCloudBookmarks, Boolean: Optional. When false,"
            " disallows macOS iCloud Bookmark sync.  Availability:"
            " Available in macOS 10.12 and later."
        )
    )


    allow_cloud_mail = AMCNullBooleanField(
        tag_text='allowCloudMail',
        verbose_name=_('Allow Cloud Mail'),
        null=True, blank=True,
        help_text=_(
            "allowCloudMail. Boolean: Optional. When false, disallows"
            " macOS Mail iCloud services. Availability: Available in"
            " macOS 10.12 and later."
        )
    )


    allow_cloud_calendar = AMCNullBooleanField(
        tag_text='allowCloudCalendar',
        verbose_name=_('Allow Cloud Calendar'),
        null=True, blank=True,
        help_text=_(
            "allowCloudCalendar, Boolean: Optional. When false,"
            " disallows macOS iCloud Calendar services. Availability:"
            " Available in macOS 10.12 and later."
        )
    )


    allow_cloud_reminders = AMCNullBooleanField(
        tag_text='allowCloudReminders',
        verbose_name=_('Allow Cloud Reminders'),
        null=True, blank=True,
        help_text=_(
            "allowCloudReminders, Boolean: Optional. When false,"
            " disallows iCloud Reminder services. Availability:"
            " Available in macOS 10.12 and later."
        )
    )


    allow_cloud_address_book = AMCNullBooleanField(
        tag_text='allowCloudAddressBook',
        verbose_name=_('Allow Cloud Address Book'),
        null=True, blank=True,
        help_text=_(
            "allowCloudAddressBook, Boolean: Optional. When false,"
            " disallows macOS iCloud Address Book services."
            " Availability: Available in macOS 10.12 and later."
        )
    )


    allow_cloud_notes = AMCNullBooleanField(
        tag_text='allowCloudNotes',
        verbose_name=_('Allow Cloud Notes'),
        null=True, blank=True,
        help_text=_(
            "allowCloudNotes, Boolean: Optional. When false, disallows"
            " macOS iCloud Notes services. Availability: Available in"
            " macOS 10.12 and later."
        )
    )


    allow_cloud_document_sync = AMCNullBooleanField(
        tag_text='allowCloudDocumentSync',
        verbose_name=_('Allow Cloud Document Sync'),
        null=True, blank=True,
        help_text=_(
            "allowCloudDocumentSync, Boolean: Optional. When false,"
            " disables document and key-value syncing to iCloud. This"
            " key is deprecated on unsupervised devices. Availability:"
            " Available in iOS 5.0 and later and in macOS 10.11 and"
            " later. "
        )
    )


    allow_cloud_keychain_sync = AMCNullBooleanField(
        tag_text='allowCloudKeychainSync',
        verbose_name=_('Allow Cloud Keychain Sync'),
        null=True, blank=True,
        help_text=_(
            "allowCloudKeychainSync, Boolean: Optional. When false,"
            " disables iCloud keychain synchronization. Default is true."
            " Availability: Available in iOS 7.0 and later and macOS"
            " 10.12 and later."
        )
    )


    allow_content_caching = AMCNullBooleanField(
        tag_text='allowContentCaching',
        verbose_name=_('Allow Content Caching'),
        null=True, blank=True,
        help_text=_(
            "allowContentCaching, Boolean: Optional. When false, this"
            " disallows content caching. Defaults to true. Availability:"
            " Available only in macOS 10.13 and later."
        )
    )


    allow_diagnostic_submission = AMCNullBooleanField(
        tag_text='allowDiagnosticSubmission',
        verbose_name=_('Allow Diagnostic Submission'),
        null=True, blank=True,
        help_text=_(
            "allowDiagnosticSubmission, Boolean: Optional. When false,"
            " this prevents the device from automatically submitting"
            " diagnostic reports to Apple. Defaults to"
            " true. Availability: Available only in iOS 6.0 and later."
        )
    )


    allow_explicit_content = AMCNullBooleanField(
        tag_text='allowExplicitContent',
        verbose_name=_('Allow Explicit Content'),
        null=True, blank=True,
        help_text=_(
            "allowExplicitContent, Boolean: Optional. When false,"
            " explicit music or video content purchased from the iTunes"
            " Store is hidden. Explicit content is marked as such by"
            " content providers, such as record labels, when sold"
            " through the iTunes Store. This key is deprecated on"
            " unsupervised devices. Availability: Available in iOS and"
            " in tvOS 11.3 and later."
        )
    )


    allow_find_my_friends_modification = AMCNullBooleanField(
        tag_text='allowFindMyFriendsModification',
        verbose_name=_('Allow Find My Friends Modification'),
        null=True, blank=True,
        help_text=_(
            "allowFindMyFriendsModification, Boolean:"
            " Optional. Supervised only. If set to false, changes to"
            " Find My Friends are disabled. Availability: Available only"
            " in iOS 7.0 and later."
        )
    )


    allow_fingerprint_for_unlock = AMCNullBooleanField(
        tag_text='allowFingerprintForUnlock',
        verbose_name=_('Allow Fingerprint For Unlock'),
        null=True, blank=True,
        help_text=_(
            "allowFingerprintForUnlock, Boolean: Optional. If false,"
            " prevents Touch ID from unlocking a device."
            " Availability: Available in iOS 7 and later and in macOS"
            " 10.12.4 and later."
        )
    )


    allow_game_center = AMCNullBooleanField(
        tag_text='allowGameCenter',
        verbose_name=_('Allow Game Center'),
        null=True, blank=True,
        help_text=_(
            "allowGameCenter, Boolean: Optional. Supervised only. When"
            " false, Game Center is disabled and its icon is removed"
            " from the Home screen. Default is true. Availability:"
            " Available only in iOS 6.0 and later."
        )
    )


    allow_global_background_fetch_when_roaming = AMCNullBooleanField(
        tag_text='allowGlobalBackgroundFetchWhenRoaming',
        verbose_name=_('Allow Global Background Fetch When Roaming'),
        null=True, blank=True,
        help_text=_(
            "allowGlobalBackgroundFetchWhenRoaming, Boolean:"
            " Optional. When false, disables global background fetch"
            " activity when an iOS phone is roaming."
        )
    )


    allow_in_app_purchases = AMCNullBooleanField(
        tag_text='allowInAppPurchases',
        verbose_name=_('Allow In App Purchases'),
        null=True, blank=True,
        help_text=_(
            "allowInAppPurchases, Boolean: Optional. When false,"
            " prohibits in-app purchasing."
        )
    )


    allow_lock_screen_control_center = AMCNullBooleanField(
        tag_text='allowLockScreenControlCenter',
        verbose_name=_('Allow Lock Screen Control Center'),
    null=True, blank=True,
        help_text=_(
            "allowLockScreenControlCenter, Boolean: Optional. If false,"
            " prevents Control Center from appearing on the Lock"
            " screen. Availability: Available in iOS 7 and later."
        )
    )


    allow_host_pairing = AMCNullBooleanField(
        tag_text='allowHostPairing',
        verbose_name=_('Allow Host Pairing'),
        null=True, blank=True,
        help_text=_(
            "allowHostPairing, Boolean: Supervised only. If set to"
            " false, host pairing is disabled with the exception of the"
            " supervision host. If no supervision host certificate has"
            " been configured, all pairing is disabled. Host pairing"
            " lets the administrator control which devices an iOS 7"
            " device can pair with. Availability: Available only in iOS"
            " 7.0 and later."
        )
    )


    allow_lock_screen_notifications_view = AMCNullBooleanField(
        tag_text='allowLockScreenNotificationsView',
        verbose_name=_('Allow Lock Screen Notifications View'),
        null=True, blank=True,
        help_text=_(
            "allowLockScreenNotificationsView, Boolean: Optional. If set"
            " to false, the Notifications view in Notification Center on"
            " the lock screen is disabled and users can’t receive"
            " notifications when the screen is locked. Availability:"
            " Available only in iOS 7.0 and later."
        )
    )


    allow_lock_screen_today_view = AMCNullBooleanField(
        tag_text='allowLockScreenTodayView',
        verbose_name=_('Allow Lock Screen Today View'),
        null=True, blank=True,
        help_text=_(
            "allowLockScreenTodayView, Boolean: Optional. If set to"
            " false, the Today view in Notification Center on the lock"
            " screen is disabled. Availability: Available only in iOS"
            " 7.0 and later."
        )
    )


    allow_multiplayer_gaming = AMCNullBooleanField(
        tag_text='allowMultiplayerGaming',
        verbose_name=_('Allow Multiplayer Gaming'),
        null=True, blank=True,
        help_text=_(
            "allowMultiplayerGaming, Boolean: Optional. When false,"
            " prohibits multiplayer gaming. This key is deprecated on"
            " unsupervised devices."
        )
    )


    allow_open_from_managed_to_unmanaged = AMCNullBooleanField(
        tag_text='allowOpenFromManagedToUnmanaged',
        verbose_name=_('Allow Open From Unmanaged To Managed'),
        null=True, blank=True,
        help_text=_(
            "allowOpenFromManagedToUnmanaged, Boolean: Optional. If"
            " false, documents in managed apps and accounts only open in"
            " other managed apps and accounts. Default is true."
            " Availability: Available only in iOS 7.0 and later."
        )
    )


    allow_open_from_unmanaged_to_managed = AMCNullBooleanField(
        tag_text='allowOpenFromUnmanagedToManaged',
        verbose_name=_('Allow Open From Managed To Unmanaged'),
        null=True, blank=True,
        help_text=_(
            "allowOpenFromUnmanagedToManaged, Boolean: Optional. If set"
            " to false, documents in unmanaged apps and accounts will"
            " only open in other unmanaged apps and accounts. Default is"
            " true. Availability: Available only in iOS 7.0 and later."
        )
    )


    allow_ota_pki_updates = AMCNullBooleanField(
        tag_text='allowOTAPKIUpdates',
        verbose_name=_('Allow OTA PKI Updates'),
        null=True, blank=True,
        help_text=_(
            "allowOTAPKIUpdates, Boolean: Optional. If false,"
            " over-the-air PKI updates are disabled. Setting this"
            " restriction to false does not disable CRL and OCSP checks."
            " Default is true. Availability: Available only in iOS 7.0"
            " and later."
        )
    )


    allow_passbook_while_locked = AMCNullBooleanField(
        tag_text='allowPassbookWhileLocked',
        verbose_name=_('Allow Passbook While Locked'),
        null=True, blank=True,
        help_text=_(
            "allowPassbookWhileLocked, Boolean: Optional. If set to"
            " false, Passbook notifications will not be shown on the"
            " lock screen.This will default to true. Availability:"
            " Available in iOS 6.0 and later."
        )
    )

    allow_photo_stream = AMCNullBooleanField(
        tag_text='allowPhotoStream',
        verbose_name=_('Allow Photo Stream'),
        null=True, blank=True,
        help_text=_(
            "allowPhotoStream, Boolean: Optional. When false, disables"
            " Photo Stream. Availability: Available in iOS 5.0 and"
            " later."
        )
    )


    allow_safari = AMCNullBooleanField(
        tag_text='allowSafari',
        verbose_name=_('Allow Safari'),
        null=True, blank=True,
        help_text=_(
            "allowSafari, Boolean: Optional. When false, the Safari web"
            " browser application is disabled and its icon removed from"
            " the Home screen. This also prevents users from opening web"
            " clips. This key is deprecated on unsupervised devices."
        )
    )


    safari_allow_auto_fill = AMCNullBooleanField(
        tag_text='safariAllowAutoFill',
        verbose_name=_('safari Allow Auto Fill'),
        null=True, blank=True,
        help_text=_(
            "safariAllowAutoFill, Boolean: Optional. When false, Safari"
            " auto-fill is disabled. Defaults to true."
        )
    )


    safari_force_fraud_warning = AMCNullBooleanField(
        tag_text='safariForceFraudWarning',
        verbose_name=_('safari Force Fraud Warning'),
        null=True, blank=True,
        help_text=_(
            "safariForceFraudWarning, Boolean: Optional. When true,"
            " Safari fraud warning is enabled. Defaults to false."
        )
    )


    safari_allow_java_script = AMCNullBooleanField(
        tag_text='safariAllowJavaScript',
        verbose_name=_('safari Allow Java Script'),
        null=True, blank=True,
        help_text=_(
            "safariAllowJavaScript, Boolean: Optional. When false,"
            " Safari will not execute JavaScript. Defaults to true."
        )
    )


    safari_allow_popups = AMCNullBooleanField(
        tag_text='safariAllowPopups',
        verbose_name=_('safari Allow Popups'),
        null=True, blank=True,
        help_text=_(
            "safariAllowPopups, Boolean: Optional. When false, Safari"
            " will not allow pop-up tabs. Defaults to true."
        )
    )


    safari_accept_cookies = AMCNullBooleanField(
        tag_text='safariAcceptCookies',
        verbose_name=_('safari Accept Cookies'),
        null=True, blank=True,
        help_text=mark_safe(_(
            "safariAcceptCookies, Real: Optional. Determines conditions"
            " under which the device will accept cookies. The user"
            " facing settings changed in iOS 11, though the possible"
            " values remain the same: <ul>"
            " <li>0: Prevent Cross-Site Tracking and Block All Cookies"
            " are enabled and the user can’t disable either setting.</li>"
            " <li>1 or 1.5: Prevent Cross-Site Tracking is enabled and"
            " the user can’t disable it. Block All Cookies is not"
            " enabled, though the user can enable it.</li>"
            " <li>2: Prevent Cross-Site Tracking is enabled and Block"
            " All Cookies is not enabled. The user can toggle either"
            " setting. (Default)</li>"
            " </ul>"
            "These are the allowed values and settings in iOS 10 and"
            " earlier:<ul>"
            " <li>0: Never</li>"
            " <li>1: Allow from current website only</li>"
            " <li>1.5: Allow from websites visited (Available in iOS 8.0"
            " and later); enter '<real>1.5</real>'<li>"
            " <li>2: Always (Default)</li>"
            " </ul>"
            "In iOS 10 and earlier, users can always pick an option that"
            " is more restrictive than the payload policy, but not a"
            " less restrictive policy. For example, with a payload value"
            " of 1.5, a user could switch to Never, but not Always"
            " Allow."
        ))
    )


    allow_shared_stream = AMCNullBooleanField(
        tag_text='allowSharedStream',
        verbose_name=_('Allow Shared Stream'),
        null=True, blank=True,
        help_text=_(
            "allowSharedStream, Boolean: Optional. If set to false,"
            " Shared Photo Stream will be disabled. This will default to"
            " true. Availability: Available in iOS 6.0 and later."
        )
    )


    allow_ui_configuration_profile_installation = AMCNullBooleanField(
        tag_text='allowUIConfigurationProfileInstallation',
        verbose_name=_('Allow UI Configuration Profile Installation'),
        null=True, blank=True,
        help_text=_(
            "allowUIConfigurationProfileInstallation, Boolean:"
            " Optional. Supervised only. If set to false, the user is"
            " prohibited from installing configuration profiles and"
            " certificates interactively. This will default to true."
            " Availability: Available in iOS 6.0 and later."
        )
    )


    allow_untrusted_tls_prompt = AMCNullBooleanField(
        tag_text='allowUntrustedTLSPrompt',
        verbose_name=_('Allow Untrusted TLS Prompt'),
        null=True, blank=True,
        help_text=_(
            "allowUntrustedTLSPrompt, Boolean: Optional. When false,"
            " automatically rejects untrusted HTTPS certificates without"
            " prompting the user. Availability: Available in iOS 5.0 and"
            " later."
        )
    )


    allow_video_conferencing = AMCNullBooleanField(
        tag_text='allowVideoConferencing',
        verbose_name=_('Allow Video Conferencing'),
        null=True, blank=True,
        help_text=_(
            "allowVideoConferencing, Boolean: Optional. When false,"
            " disables video conferencing. This key is deprecated on"
            " unsupervised devices."
        )
    )


    allow_voice_dialing = AMCNullBooleanField(
        tag_text='allowVoiceDialing',
        verbose_name=_('Allow Voice Dialing'),
        null=True, blank=True,
        help_text=_(
            "allowVoiceDialing, Boolean: Optional. When false, disables"
            " voice dialing if the device is locked with a"
            " passcode. Default is true."
        )
    )

    allow_you_tube = AMCNullBooleanField(
        tag_text='allowYouTube',
        verbose_name=_('Allow You Tube'),
        null=True, blank=True,
        help_text=_(
            "allowYouTube, Boolean: Optional. When false, the YouTube"
            " application is disabled and its icon is removed from the"
            " Home screen. This key is ignored in iOS 6 and later"
            " because the YouTube app is not provided."
        )
    )


    allow_itunes = AMCNullBooleanField(
        tag_text='allowiTunes',
        verbose_name=_('Allow iTunes'),
        null=True, blank=True,
        help_text=_(
            "allowiTunes, Boolean: Optional. When false, the iTunes"
            " Music Store is disabled and its icon is removed from the"
            " Home screen. Users cannot preview, purchase, or download"
            " content. This key is deprecated on unsupervised devices."
        )
    )


    allow_itunes_file_sharing = AMCNullBooleanField(
        tag_text='allowiTunesFileSharing',
        verbose_name=_('Allow iTunes File Sharing'),
        null=True, blank=True,
        help_text=_(
            "allowiTunesFileSharing, Boolean: Optional. When false,"
            " iTunes application file sharing services are"
            " disabled. Availability: Available in macOS 10.13 and"
            " later."
        )
    )


    autonomous_single_app_mode_permitted_app_ids = AMCNullBooleanField(
        tag_text='Autonomous Single App Mode Permitted App IDs',
        verbose_name=_('Autonomous Single App Mode Permitted App IDs'),
        null=True, blank=True,
        help_text=_(
            "autonomousSingleAppModePermittedAppIDs: Array of Strings:"
            " Optional. Supervised only. If present, allows apps"
            " identified by the bundle IDs listed in the array to"
            " autonomously enter Single App Mode. Availability:"
            " Available only in iOS 7.0 and later."
        )
    )


    force_assistant_profanity_filter = AMCNullBooleanField(
        tag_text='forceAssistantProfanityFilter',
        verbose_name=_('Force Assistant Profanity Filter'),
        null=True, blank=True,
        help_text=_(
            "forceAssistantProfanityFilter, Boolean: Optional."
            " Supervised only. When true, forces the use of the"
            " profanity filter assistant."
        )
    )


    force_encrypted_backup = AMCNullBooleanField(
        tag_text='forceEncryptedBackup',
        verbose_name=_('Force Encrypted Backup'),
        null=True, blank=True,
        help_text=_(
            "forceEncryptedBackup, Boolean: Optional. When true,"
            " encrypts all backups."
        )
    )


    force_itunes_store_password_entry = AMCNullBooleanField(
        tag_text='forceITunesStorePasswordEntry',
        verbose_name=_('Force iTunes Store Password Entry'),
        null=True, blank=True,
        help_text=_(
            "forceITunesStorePasswordEntry, Boolean: Optional. When"
            " true, forces user to enter their iTunes password for each"
            " transaction. Availability: Available in iOS 5.0 and later."
        )
    )


    force_limit_ad_tracking = AMCNullBooleanField(
        tag_text='forceLimitAdTracking',
        verbose_name=_('Force Limit Ad Tracking'),
        null=True, blank=True,
        help_text=_(
            "forceLimitAdTracking, Boolean: Optional. If true, limits ad"
            " tracking. Default is false. Availability: Available only"
            " in iOS 7.0 and later."
        )
    )


    force_air_play_outgoing_requests_pairing_password = AMCNullBooleanField(
        tag_text='forceAirPlayOutgoingRequestsPairingPassword',
        verbose_name=_('Force Air Play Outgoing Requests Pairing Password'),
        null=True, blank=True,
        help_text=_(
            "forceAirPlayOutgoingRequestsPairingPassword, Boolean:"
            " Optional. If set to true, forces all devices receiving"
            " AirPlay requests from this device to use a pairing"
            " password. Default is false. Availability: Available only"
            " in iOS 7.1 and later."
        )
    )


    force_air_play_incoming_requests_pairing_password = AMCNullBooleanField(
        tag_text='forceAirPlayIncomingRequestsPairingPassword',
        verbose_name=_('Force Air Play Incoming Requests Pairing Password'),
        null=True, blank=True,
        help_text=_(
            "forceAirPlayIncomingRequestsPairingPassword, Boolean:"
            " Optional. If set to true, forces all devices sending AirPlay"
            " requests to this device to use a pairing password. Default"
            " is false. Availability: Available only in Apple TV 6.1 to"
            " tvOS 10.1. It is recommended to use the AirPlay Security"
            " Payload."
        )
    )


    allow_managed_apps_cloud_sync = AMCNullBooleanField(
        tag_text='allowManagedAppsCloudSync',
        verbose_name=_('Allow Managed Apps Cloud Sync'),
        null=True, blank=True,
        help_text=_(
            "allowManagedAppsCloudSync, Boolean: Optional. If set to"
            " false, prevents managed applications from using iCloud"
            " sync."
        )
    )


    allow_erase_content_and_settings = AMCNullBooleanField(
        tag_text='allowEraseContentAndSettings',
        verbose_name=_('Allow Erase Content And Settings'),
        null=True, blank=True,
        help_text=_(
            "allowEraseContentAndSettings, Boolean: Supervised only. If"
            " set to false, disables the “Erase All Content And"
            " Settings” option in the Reset UI."
        )
    )


    allow_spotlight_internet_results = AMCNullBooleanField(
        tag_text='allowSpotlightInternetResults',
        verbose_name=_('Allow Spotlight Internet Results'),
        null=True, blank=True,
        help_text=_(
            "allowSpotlightInternetResults, Boolean: Supervised only. If"
            " set to false, Spotlight will not return Internet search"
            " results. Availability: Available in iOS and in macOS 10.11"
            " and later."
        )
    )


    allow_enabling_restrictions = AMCNullBooleanField(
        tag_text='allowEnablingRestrictions',
        verbose_name=_('Allow Enabling Restrictions'),
        null=True, blank=True,
        help_text=_(
            "allowEnablingRestrictions, Boolean: Supervised only. If set"
            " to false, disables the \"Enable Restrictions\" option in"
            " the Restrictions UI in Settings."
        )
    )


    allow_activity_continuation = AMCNullBooleanField(
        tag_text='allowActivityContinuation',
        verbose_name=_('Allow Activity Continuation'),
        null=True, blank=True,
        help_text=_(
            "allowActivityContinuation, Boolean: If set to false,"
            " Activity Continuation will be disabled. Defaults to true."
        )
    )


    allow_enterprise_book_backup = AMCNullBooleanField(
        tag_text='allowEnterpriseBookBackup',
        verbose_name=_('Allow Enterprise Book Backup'),
        null=True, blank=True,
        help_text=_(
            "allowEnterpriseBookBackup, Boolean: If set to false,"
            " Enterprise books will not be backed up. Defaults to true."
        )
    )


    allow_enterprise_book_metadata_sync = AMCNullBooleanField(
        tag_text='allowEnterpriseBookMetadataSync',
        verbose_name=_('Allow Enterprise Book Metadata Sync'),
        null=True, blank=True,
        help_text=_(
            "allowEnterpriseBookMetadataSync, Boolean: If set to false,"
            " Enterprise books notes and highlights will not be"
            " synced. Defaults to true."
        )
    )


    allow_podcasts = AMCNullBooleanField(
        tag_text='allowPodcasts',
        verbose_name=_('Allow Podcasts'),
        null=True, blank=True,
        help_text=_(
            "allowPodcasts, Boolean: Supervised only. If set to false,"
            " disables podcasts. Defaults to true. Availability:"
            " Available in iOS 8.0 and later."
        )
    )


    allow_definition_lookup = AMCNullBooleanField(
        tag_text='allowDefinitionLookup',
        verbose_name=_('Allow Definition Lookup'),
        null=True, blank=True,
        help_text=_(
            "allowDefinitionLookup, Boolean: Supervised only. If set to"
            " false, disables definition lookup. Defaults to true."
            " Availability: Available in iOS 8.1.3 and later and in"
            " macOS 10.11.2 and later."
        )
    )


    allow_predictive_keyboard = AMCNullBooleanField(
        tag_text='allowPredictiveKeyboard',
        verbose_name=_('Allow Predictive Keyboard'),
        null=True, blank=True,
        help_text=_(
           "allowPredictiveKeyboard, Boolean: Supervised only. If set"
           " to false, disables predictive keyboards. Defaults to"
           " true. Availability: Available in iOS 8.1.3 and later."
        )
    )


    allow_auto_correction = AMCNullBooleanField(
        tag_text='allowAutoCorrection',
        verbose_name=_('Allow Auto Correction'),
        null=True, blank=True,
        help_text=_(
            "allowAutoCorrection, Boolean: Supervised only. If set to"
            " false, disables keyboard auto-correction. Defaults to"
            " true. Availability: Available in iOS 8.1.3 and later."
        )
    )


    allow_spell_check = AMCNullBooleanField(
        tag_text='allowSpellCheck',
        verbose_name=_('Allow Spell Check'),
        null=True, blank=True,
        help_text=_(
            "allowSpellCheck, Boolean: Supervised only. If set to false,"
            " disables keyboard spell-check. Defaults to true."
            " Availability: Available in iOS 8.1.3 and later."
        )
    )


    force_watch_wrist_detection = AMCNullBooleanField(
        tag_text='forceWatchWristDetection',
        verbose_name=_('Force Watch Wrist Detection'),
        null=True, blank=True,
        help_text=_(
            "forceWatchWristDetection, Boolean: If set to true, a paired"
            " Apple Watch will be forced to use Wrist Detection."
            " Defaults to false. Availability: Available in iOS 8.2 and"
            " later."
        )
    )


    allow_music_service = AMCNullBooleanField(
        tag_text='allowMusicService',
        verbose_name=_('Allow Music Service'),
        null=True, blank=True,
        help_text=_(
            "allowMusicService, Boolean: Supervised only. If set to"
            " false, Music service is disabled and Music app reverts to"
            " classic mode. Defaults to true. Availability: Available in"
            " iOS 9.3 and later and macOS 10.12 and later."
        )
    )


    allow_cloud_photo_library = AMCNullBooleanField(
        tag_text='allowCloudPhotoLibrary',
        verbose_name=_('Allow Cloud Photo Library'),
        null=True, blank=True,
        help_text=_(
            "allowCloudPhotoLibrary, Boolean: If set to false, disables"
            " iCloud Photo Library. Any photos not fully downloaded from"
            " iCloud Photo Library to the device will be removed from"
            " local storage. Availability: Available in iOS 9.0 and"
            " later and in macOS 10.12 and later."
        )
    )


    allow_news = AMCNullBooleanField(
        tag_text='allowNews',
        verbose_name=_('Allow News'),
        null=True, blank=True,
        help_text=_(
            "allowNews, Boolean: Supervised only. If set to false,"
            " disables News. Defaults to true. Availability: Available"
            " in iOS 9.0 and later."
        )
    )


    force_air_drop_unmanaged = AMCNullBooleanField(
        tag_text='forceAirDropUnmanaged',
        verbose_name=_('Force Air Drop Unmanaged'),
        null=True, blank=True,
        help_text=_(
            "forceAirDropUnmanaged, Boolean: Optional. If set to true,"
            " causes AirDrop to be considered an unmanaged drop"
            " target. Defaults to false. Availability: Available in iOS"
            " 9.0 and later."
        )
    )


    allow_ui_app_installation = AMCNullBooleanField(
        tag_text='allowUIAppInstallation',
        verbose_name=_('Allow UI App Installation'),
        null=True, blank=True,
        help_text=_(
            "allowUIAppInstallation, Boolean: Supervised only. When"
            " false, the App Store is disabled and its icon is removed"
            " from the Home screen. However, users may continue to use"
            " Host apps (iTunes, Configurator) to install or update"
            " their apps. Defaults to true. Availability: Available in"
            " iOS 9.0 and later."
        )
    )


    allow_screen_shot = AMCNullBooleanField(
        tag_text='allowScreenShot',
        verbose_name=_('Allow Screen Shot'),
        null=True, blank=True,
        help_text=_(
            "allowScreenShot, Boolean: Optional. If set to false, users"
            " can’t save a screenshot of the display and are prevented"
            " from capturing a screen recording; it also prevents the"
            " Classroom app from observing remote screens. Defaults to"
            "true. Availability: Updated in iOS 9.0 to include screen"
            " recordings."
        )
    )


    allow_keyboard_shortcuts = AMCNullBooleanField(
        tag_text='allowKeyboardShortcuts',
        verbose_name=_('Allow Keyboard Shortcuts'),
        null=True, blank=True,
        help_text=_(
            "allowKeyboardShortcuts, Boolean: Supervised only. If set to"
            " false, keyboard shortcuts cannot be used. Defaults to"
            " true. Availability: Available in iOS 9.0 and later."
        )
    )


    allow_paired_watch = AMCNullBooleanField(
        tag_text='allowPairedWatch',
        verbose_name=_('Allow Paired Watch'),
        null=True, blank=True,
        help_text=_(
            "allowPairedWatch, Boolean: Supervised only. If set to"
            " false, disables pairing with an Apple Watch. Any currently"
            " paired Apple Watch is unpaired and erased. Defaults to"
            " true. Availability: Available in iOS 9.0 and later."
        )
    )


    allow_passcode_modification = AMCNullBooleanField(
        tag_text='allowPasscodeModification',
        verbose_name=_('Allow Passcode Modification'),
        null=True, blank=True,
        help_text=_(
            "allowPasscodeModification, Boolean: Supervised only. If set"
            " to false, prevents the device passcode from being added,"
            " changed, or removed. Defaults to true. This restriction is"
            " ignored by shared iPads. Availability: Available in iOS"
            " 9.0 and later."
        )
    )


    allow_device_name_modification = AMCNullBooleanField(
        tag_text='allowDeviceNameModification',
        verbose_name=_('Allow Device Name Modification'),
        null=True, blank=True,
        help_text=_(
            "allowDeviceNameModification, Boolean: Supervised only. If"
            " set to false, prevents device name from being"
            " changed. Defaults to true. Availability: Available in iOS"
            " 9.0 and later."
        )
    )


    allow_wallpaper_modification = AMCNullBooleanField(
        tag_text='allowWallpaperModification',
        verbose_name=_('Allow Wallpaper Modification'),
        null=True, blank=True,
        help_text=_(
            "allowWallpaperModification, Boolean: Supervised only. If"
            " set to false, prevents wallpaper from being"
            " changed. Defaults to true. Availability: Available in iOS"
            " 9.0 and later."
        )
    )


    allow_automatic_app_downloads = AMCNullBooleanField(
        tag_text='allowAutomaticAppDownloads',
        verbose_name=_('Allow Automatic App Downloads'),
        null=True, blank=True,
        help_text=_(
            "allowAutomaticAppDownloads, Boolean: Supervised only. If"
            " set to false, prevents automatic downloading of apps"
            " purchased on other devices. Does not affect updates to"
            " existing apps. Defaults to true. Availability: Available"
            " in iOS 9.0 and later."
        )
    )


    allow_enterprise_app_trust = AMCNullBooleanField(
        tag_text='allowEnterpriseAppTrust',
        verbose_name=_('Allow Enterprise App Trust'),
        null=True, blank=True,
        help_text=_(
            "allowEnterpriseAppTrust, Boolean: If set to false removes"
            " the Trust Enterprise Developer button in"
            " Settings->General->Profiles & Device Management,"
            " preventing apps from being provisioned by universal"
            " provisioning profiles. This restriction applies to free"
            " developer accounts but it does not apply to enterprise app"
            " developers who are trusted because their apps were pushed"
            " via MDM, nor does it revoke previously granted"
            " trust. Defaults to true. Availability: Available in iOS"
            " 9.0 and later."
        )
    )


    allow_radio_service = AMCNullBooleanField(
        tag_text='allowRadioService',
        verbose_name=_('Allow Radio Service'),
        null=True, blank=True,
        help_text=_(
            "allowRadioService, Boolean: Supervised only. If set to"
            " false, Apple Music Radio is disabled. Defaults to"
            "true. Availability: Available in iOS 9.3 and later."
        )
    )


    blacklisted_app_bundle_ids = AMCNullBooleanField(
        tag_text='blacklistedAppBundleIDs',
        verbose_name=_('Blacklisted App Bundle IDs'),
        null=True, blank=True,
        help_text=_(
            "blacklistedAppBundleIDs, Array of Strings: Supervised"
            " only. If present, prevents bundle IDs listed in the array"
            " from being shown or launchable. Availability: Available in"
            " iOS 9.3 and later."
        )
    )


    whitelisted_app_bundle_ids = AMCNullBooleanField(
        tag_text='whitelistedAppBundleIDs',
        verbose_name=_('Whitelisted App Bundle IDs'),
        null=True, blank=True,
        help_text=_(
            "whitelistedAppBundleIDs, Array of Strings: Supervised"
            " only. If present, allows only bundle IDs listed in the"
            " array from being shown or launchable. Availability:"
            " Available in iOS 9.3 and later."
        )
    )


    allow_notifications_modification = AMCNullBooleanField(
        tag_text='allowNotificationsModification',
        verbose_name=_('Allow Notifications Modification'),
        null=True, blank=True,
        help_text=_(
            "allowNotificationsModification, Boolean: Supervised"
            " only. If set to false, notification settings cannot be"
            " modified. Defaults to true. Availability: Available in iOS"
            "9.3 and later."
        )
    )


    allow_remote_screen_observation = AMCNullBooleanField(
        tag_text='allowRemoteScreenObservation',
        verbose_name=_('Allow Remote Screen Observation'),
        null=True, blank=True,
        help_text=_(
            "allowRemoteScreenObservation, Boolean: If set to false,"
            " remote screen observation by the Classroom app is"
            " disabled. Defaults to true. This key should be nested"
            " beneath allowScreenShot as a sub-restriction. If"
            " allowScreenShot is set to false, it also prevents the"
            " Classroom app from observing remote screens. Availability:"
            " Available in iOS 9.3 and later."
        )
    )


    allow_diagnostic_submission_modification = AMCNullBooleanField(
        tag_text='allowDiagnosticSubmissionModification',
        verbose_name=_('Allow Diagnostic Submission Modification'),
        null=True, blank=True,
        help_text=_(
            "allowDiagnosticSubmissionModification, Boolean: Supervised"
            " only. If set to false, the diagnostic submission and app"
            " analytics settings in the Diagnostics & Usage pane in"
            " Settings cannot be modified. Defaults to true."
            " Availability: Available in iOS 9.3.2 and later."
        )
    )


    allow_bluetooth_modification = AMCNullBooleanField(
        tag_text='allowBluetoothModification',
        verbose_name=_('Allow Bluetooth Modification'),
        null=True, blank=True,
        help_text=_(
            "allowBluetoothModification, Boolean: Supervised only. If"
            "set to false, prevents modification of Bluetooth"
            " settings. Defaults to true. Availability: Available in iOS"
            " 10.0 and later."
        )
    )


    allow_auto_unlock = AMCNullBooleanField(
        tag_text='allowAutoUnlock',
        verbose_name=_('Allow Auto Unlock'),
        null=True, blank=True,
        help_text=_(
            "allowAutoUnlock, Boolean: If set to false, disallows macOS"
            " auto unlock. Defaults to true. Availability: Available"
            " only in macOS 10.12 and later."
        )
    )


    allow_cloud_desktop_and_documents = AMCNullBooleanField(
        tag_text='allowCloudDesktopAndDocuments',
        verbose_name=_('Allow Cloud Desktop And Documents'),
        null=True, blank=True,
        help_text=_(
            "allowCloudDesktopAndDocuments, Boolean: If set to false,"
            " disallows macOS cloud desktop and document services."
            " Defaults to true. Availability: Available only in macOS"
            " 10.12.4 and later."
        )
    )


    allow_dictation = AMCNullBooleanField(
        tag_text='allowDictation',
        verbose_name=_('Allow Dictation'),
        null=True, blank=True,
        help_text=_(
            "allowDictation, Boolean: Supervised only. If set to false,"
            " disallows dictation input. Defaults to true. Availability:"
            " Available only in iOS 10.3 and later."
        )
    )


    force_wifi_whitelisting = AMCNullBooleanField(
        tag_text='forceWiFiWhitelisting',
        verbose_name=_('Force WiFi Whitelisting'),
        null=True, blank=True,
        help_text=_(
            "forceWiFiWhitelisting, Boolean: Optional. Supervised"
            " only. If set to true, the device can join Wi-Fi networks"
            " only if they were set up through a configuration profile."
            " Defaults to false. Availability: Available only in iOS"
            " 10.3 and later."
        )
    )


    force_unprompted_managed_classroom_screen_observation = AMCNullBooleanField(
        tag_text='forceUnpromptedManagedClassroomScreenObservation',
        verbose_name=_('Force Unprompted Managed Classroom Screen Observation'),
        null=True, blank=True,
        help_text=_(
            "forceUnpromptedManagedClassroomScreenObservation, Boolean:"
            " Deprecated in iOS 11. Use"
            " forceClassroomUnpromptedScreenObservation instead."
        )
    )


    allow_air_print = AMCNullBooleanField(
        tag_text='allowAirPrint',
        verbose_name=_('Allow Air Print'),
        null=True, blank=True,
        help_text=_(
            "allowAirPrint, Boolean: Supervised only. If set to false,"
            " disallow AirPrint. Defaults to true. Availability:"
            " Available in iOS 11.0 and later and macOS 10.13 and later."
        )
    )


    allow_air_print_credentials_storage = AMCNullBooleanField(
        tag_text='allowAirPrintCredentialsStorage',
        verbose_name=_('Allow Air Print Credentials Storage'),
        null=True, blank=True,
        help_text=_(
            "allowAirPrintCredentialsStorage, Boolean: Supervised"
            " only. If set to false, disallows keychain storage of"
            " username and password for Airprint. Defaults to true."
            " Availability: Available only in iOS 11.0 and later."
        )
    )


    force_air_print_trusted_tls_requirement = AMCNullBooleanField(
        tag_text='forceAirPrintTrustedTLSRequirement',
        verbose_name=_('Force Air Print Trusted TLS Requirement'),
        null=True, blank=True,
        help_text=_(
            "forceAirPrintTrustedTLSRequirement, Boolean: Supervised"
            " only. If set to true, requires trusted certificates for"
            " TLS printing communication. Defaults to false."
            " Availability: Available in iOS 11.0 and later and macOS"
            " 10.13 and later."
        )
    )


    allow_air_printi_beacon_discovery = AMCNullBooleanField(
        tag_text='allowAirPrintiBeaconDiscovery',
        verbose_name=_('Allow Air Printi Beacon Discovery'),
        null=True, blank=True,
        help_text=_(
            "allowAirPrintiBeaconDiscovery, Boolean: Supervised only. If"
            " set to false, disables iBeacon discovery of AirPrint"
            " printers. This prevents spurious AirPrint Bluetooth"
            " beacons from phishing for network traffic. Defaults to"
            " true. Availability: Available in iOS 11.0 and later and"
            " macOS 10.13 and later."
        )
    )


    allow_proximity_setup_to_new_device = AMCNullBooleanField(
        tag_text='allowProximitySetupToNewDevice',
        verbose_name=_('Allow Proximity Setup To New Device'),
        null=True, blank=True,
        help_text=_(
            "allowProximitySetupToNewDevice, Boolean: Supervised"
            " only. If set to false, disables the prompt to setup new"
            " devices that are nearby. Defaults to true. Availability:"
            " Available only in iOS 11.0 and later."
        )
    )


    allow_system_app_removal = AMCNullBooleanField(
        tag_text='allowSystemAppRemoval',
        verbose_name=_('Allow System App Removal'),
        null=True, blank=True,
        help_text=_(
            "allowSystemAppRemoval, Boolean: Supervised only. If set to"
            " false, disables the removal of system apps from the"
            " device. Defaults to true. Availability: Available only in"
            " iOS 11.0 and later."
        )
    )


    allow_vpn_creation = AMCNullBooleanField(
        tag_text='allowVPNCreation',
        verbose_name=_('Allow VPN Creation'),
        null=True, blank=True,
        help_text=_(
            "allowVPNCreation, Boolean: Supervised only. If set to"
            " false, disallow the creation of VPN configurations."
            " Defaults to true. Availability: Available only in iOS 11.0"
            " and later."
        )
    )


    force_delayed_software_updates = AMCNullBooleanField(
        tag_text='forceDelayedSoftwareUpdates',
        verbose_name=_('Force Delayed Software Updates'),
        null=True, blank=True,
        help_text=_(
            "forceDelayedSoftwareUpdates, Boolean: Supervised only. If"
            " set to true, delays user visibility of Software Updates."
            " Defaults to false. Availability: Available in iOS 11.3 and"
            " later and macOS 10.13 and later."
        )
    )


    enforced_software_update_delay = AMCNullBooleanField(
        tag_text='enforcedSoftwareUpdateDelay',
        verbose_name=_('Enforced Software Update Delay'),
        null=True, blank=True,
        help_text=_(
            "enforcedSoftwareUpdateDelay, Integer: Supervised only. This"
            " restriction allows the admin to set how many days a"
            " software update on the device will be delayed. With this"
            " restriction in place, the user will not see a software"
            " update until the specified number of days after the"
            " software update release date. The max is 90 days and the"
            " default value is 30. Availability: Available in iOS 11.3"
            "and later and macOS 10.13.4 and later."
        )
    )


    force_authentication_before_auto_fill = AMCNullBooleanField(
        tag_text='forceAuthenticationBeforeAutoFill',
        verbose_name=_('Force Authentication Before Auto Fill'),
        null=True, blank=True,
        help_text=_(
            "forceAuthenticationBeforeAutoFill, Boolean:"
            " Optional. Supervised only. If set to true, the uer will"
            " have to authenticate before passwords or credit card"
            " information can be autofilled in Safari and Apps. If this"
            " restriction is not enforced, the user can toggle this"
            " feature in settings. Only supported on devices with"
            " FaceID. Defaults to true. Availability: Available only in"
            " iOS 11.0 and later."
        )
    )


    force_classroom_automatically_join_classes = AMCNullBooleanField(
        tag_text='forceClassroomAutomaticallyJoinClasses',
        verbose_name=_('Force Classroom Automatically Join Classes'),
        null=True, blank=True,
        help_text=_(
            "forceClassroomAutomaticallyJoinClasses, Boolean:"
            " Optional. Supervised only. If set to true, automatically"
            " give permission to the teacher’s requests without"
            " prompting the student. Defaults to false. Availability:"
            " Available only in iOS 11.0 and later."
        )
    )


    force_classroom_request_permission_to_leave_classes = AMCNullBooleanField(
        tag_text='forceClassroomRequestPermissionToLeaveClasses',
        verbose_name=_('Force Classroom Request Permission To Leave Classes'),
        null=True, blank=True,
        help_text=_(
            "forceClassroomRequestPermissionToLeaveClasses, Boolean:"
            " Optional. Supervised only. If set to true, a student"
            " enrolled in an unmanaged course via Classroom will request"
            " permission from the teacher when attempting to leave the"
            " course. Defaults to false. Availability: Available only in"
            " iOS 11.3 and later."
        )
    )


    force_classroom_unprompted_app_and_device_lock = AMCNullBooleanField(
        tag_text='forceClassroomUnpromptedAppAndDeviceLock',
        verbose_name=_('Force Classroom Unprompted App And Device Lock'),
        null=True, blank=True,
        help_text=_(
            "forceClassroomUnpromptedAppAndDeviceLock, Boolean:"
            " Optional. Supervised only. If set to true, allow the"
            " teacher to lock apps or the device without prompting the"
            " student. Defaults to false. Availability: Available only"
            " in iOS 11.0 and later."
        )
    )


    force_classroom_unprompted_screen_observation = AMCNullBooleanField(
        tag_text='forceClassroomUnpromptedScreenObservation',
        verbose_name=_('Force Classroom Unprompted Screen Observation'),
        null=True, blank=True,
        help_text=_(
            "forceClassroomUnpromptedScreenObservation, Boolean:"
            " Optional. Supervised only. If set to true, and"
            " ScreenObservationPermissionModificationAllowed is also"
            " true in the Education payload, a student enrolled in a"
            " managed course via the Classroom app will automatically"
            " give permission to that course's teacher’s requests to"
            " observe the student’s screen without prompting the"
            " student. Defaults to false. Availability: Available only"
            " in iOS 11.0 and later."
        )
    )


    rating_region = AMCNullBooleanField(
        tag_text='ratingRegion',
        verbose_name=_('Rating Region'),
        null=True, blank=True,
        help_text=mark_safe(_(
            "ratingRegion, String. This 2-letter key is used by profile"
            " tools to display the proper ratings for given region."
            " Possible values:<ul>"
            " <li>au: Australia</li>"
            " <li>ca: Canada</li>"
            " <li>fr: France</li>"
            " <li>de: Germany</li>"
            " <li>ie: Ireland</li>"
            " <li>jp: Japan</li>"
            " <li>nz: New Zealand</li>"
            " <li>gb: United Kingdom</li>"
            " <li>us: United States</li>"
            "</ul>"
            "Availability: Available in iOS and tvOS 11.3 and later."
        ))
    )


    rating_movies = AMCNullBooleanField(
        tag_text='ratingMovies',
        verbose_name=_('Rating Movies'),
        null=True, blank=True,
        help_text=mark_safe(_(
            "ratingMovies, Integer. This value defines the maximum level"
            " of movie content that is allowed on the device. Possible"
            " values (with the US description of the rating level):<ul>"
            "<li>1000: All</li>"
            "<li>500: NC-17</li>"
            "<li>400: R</li>"
            "<li>300: PG-13</li>"
            "<li>200: PG</li>"
            "<li>100: G</li>"
            "<li>0: None</li>"
            "</ul>"
            "Availability: Available only in iOS and tvOS 11.3 and later."
        ))
    )


    rating_tv_shows = AMCNullBooleanField(
        tag_text='ratingTVShows',
        verbose_name=_('Rating TV Shows'),
        null=True, blank=True,
        help_text=mark_safe(_(
            "ratingTVShows, Integer. This value defines the maximum"
            " level of TV content that is allowed on the device."
            " Possible values (with the US description of the rating"
            " level):<ul>"
            "<li>1000: All</li>"
            "<li>600: TV-MA</li>"
            "<li>500: TV-14</li>"
            "<li>400: TV-PG</li>"
            "<li>300: TV-G</li>"
            "<li>200: TV-Y7</li>"
            "<li>100: TV-Y</li>"
            "<li>0: None</li>"
            "</ul>"
            "Availability: Available only in iOS and tvOS 11.3 and"
            " later."
        ))
    )


    rating_apps = AMCNullBooleanField(
        tag_text='ratingApps',
        verbose_name=_('Rating Apps'),
        null=True, blank=True,
        help_text=mark_safe(_(
            "ratingApps, Integer. This value defines the maximum level"
            " of app content that is allowed on the device. Possible"
            " values (with the US description of the rating level):"
            "<ul>"
            "<li>1000: All</li>"
            "<li>600: 17+</li>"
            "<li>300: 12+</li>"
            "<li>200: 9+</li>"
            "<li>100: 4+</li>"
            "<li>0: None</li>"
            "</ul>"
            "Availability: Available only in iOS 5 and tvOS 11.3 and"
            " later."
        ))
    )

PAYLOAD_TYPES = {
    'com.apple.mail.managed': EmailPayload,
    'com.apple.applicationaccess': RestrictionsPayload
}
