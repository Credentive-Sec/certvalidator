# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import x509, crl
from oscrypto import asymmetric
import oscrypto.errors

from ._errors import pretty_message
from ._types import str_cls, type_name
from .context import ValidationContext
from .errors import (
    CRLNoMatchesError,
    CRLValidationError,
    CRLValidationIndeterminateError,
    InvalidCertificateError,
    OCSPNoMatchesError,
    OCSPValidationIndeterminateError,
    PathValidationError,
    RevokedError,
    SoftFailError,
)
from .path import ValidationPath

def validate_name(validation_context, path):
    pass
