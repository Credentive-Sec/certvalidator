# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function
from asyncio.proactor_events import _ProactorBasePipeTransport

from asn1crypto import x509, crl
from importlib_metadata import NullFinder
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
    
    
    if not isinstance(path, ValidationPath):
        raise TypeError(pretty_message(
            '''
            path must be an instance of certvalidator.path.ValidationPath,
            not %s
            ''',
            type_name(path)
    ))

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
    ))

    # Inputs

    trust_anchor = path.first

    # We skip the trust anchor when measuring the path since technically
    # the trust anchor is not part of the path
    path_length = len(path) - 1

    # We don't accept any certificate policy or name constraint values as input
    # and instead just start allowing everything during initialization

    # Step 1: initialization

    # Step 1 a ignored, since we are only focusing on path

    # Steps 1 b-c set name constraints. Use values present in trust anchor, or set to None
    if trust_anchor.name_constraints is not None:
        path_permitted_subtrees = trust_anchor.name_constraints.permitted_subtrees
        path_excluded_subtrees = trust_anchor.name_constraints.excluded_subtrees
    else:
        path_permitted_subtrees = None
        path_excluded_subtrees = None

    # Steps 1 d-f

    # Steps 1 g-i
    working_public_key = trust_anchor.public_key
    # Step 1 j
    working_issuer_name = trust_anchor.subject
    # Step 1 k
    max_path_length = path_length
    if trust_anchor.max_path_length is not None:
        max_path_length = trust_anchor.max_path_length

    # Step 2: basic processing
    index = 1
    last_index = len(path) - 1

    completed_path = ValidationPath(trust_anchor)
    validation_context.record_validation(trust_anchor, completed_path)

    cert = trust_anchor
    while index <= last_index:
        cert = path[index]

        # Step 2 a 1 Skipped because not related to name constraints
        
        # Step 2 a 2 Skipped because not related to name constraints

        # Step 2 a 3 - CRL/OCSP Skipped because not related to name constraints
        # Step 2 a 4
        if cert.issuer != working_issuer_name:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the %s issuer name
                could not be matched
                ''',
                _cert_type(index, last_index, end_entity_name_override),
            ))

        # Steps 2 b-c 
        #   (b)  If certificate i is self-issued and it is not the final
        #        certificate in the path, skip this step for certificate i.
        #        Otherwise, verify that the subject name is within one of the
        #        permitted_subtrees for X.500 distinguished names, and verify
        #        that each of the alternative names in the subjectAltName
        #        extension (critical or non-critical) is within one of the
        #        permitted_subtrees for that name type.

        #   (c)  If certificate i is self-issued and it is not the final
        #        certificate in the path, skip this step for certificate i.
        #        Otherwise, verify that the subject name is not within any of
        #        the excluded_subtrees for X.500 distinguished names, and
        #        verify that each of the alternative names in the
        #        subjectAltName extension (critical or non-critical) is not
        #        within any of the excluded_subtrees for that name type.
        if cert.self_issued and index < last_index:
            # skip this step for this certificate
            pass
        else:
            # Cut the DN in the cert to the same length as the RDN in the 
            # permitted subtree, then compare for equality
            #
            cert_subtree = cert.subject
            if path_permitted_subtrees != None:
                while len(cert_subtree) > len(path_permitted_subtrees):
                    
                    pass

        # Steps 2 d
        if cert.certificate_policies_value and valid_policy_tree is not None:
            cert_any_policy = None
            cert_policy_identifiers = set()

            # Step 2 d 1
            for policy in cert.certificate_policies_value:
                policy_identifier = policy['policy_identifier'].native

                if policy_identifier == 'any_policy':
                    cert_any_policy = policy
                    continue

                cert_policy_identifiers.add(policy_identifier)

                policy_qualifiers = policy['policy_qualifiers']

                policy_id_match = False
                parent_any_policy = None

                # Step 2 d 1 i
                for node in valid_policy_tree.at_depth(index - 1):
                    if node.valid_policy == 'any_policy':
                        parent_any_policy = node
                    if policy_identifier not in node.expected_policy_set:
                        continue
                    policy_id_match = True
                    node.add_child(
                        policy_identifier,
                        policy_qualifiers,
                        set([policy_identifier])
                    )

                # Step 2 d 1 ii
                if not policy_id_match and parent_any_policy:
                    parent_any_policy.add_child(
                        policy_identifier,
                        policy_qualifiers,
                        set([policy_identifier])
                    )

            # Step 2 d 2
            if cert_any_policy and (inhibit_any_policy > 0 or (index < path_length and cert.self_issued)):
                for node in valid_policy_tree.at_depth(index - 1):
                    for expected_policy_identifier in node.expected_policy_set:
                        if expected_policy_identifier not in cert_policy_identifiers:
                            node.add_child(
                                expected_policy_identifier,
                                cert_any_policy['policy_qualifiers'],
                                set([expected_policy_identifier])
                            )

            # Step 2 d 3
            for node in valid_policy_tree.walk_up(index - 1):
                if not node.children:
                    node.parent.remove_child(node)
            if len(valid_policy_tree.children) == 0:
                valid_policy_tree = None

        # Step 2 e
        if cert.certificate_policies_value is None:
            valid_policy_tree = None

        # Step 2 f
        if valid_policy_tree is None and explicit_policy <= 0:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because there is no valid set
                of policies for %s
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True),
            ))

        if index != last_index:
            # Step 3: prepare for certificate index+1

            if cert.policy_mappings_value:
                policy_map = {}
                for mapping in cert.policy_mappings_value:
                    issuer_domain_policy = mapping['issuer_domain_policy'].native
                    subject_domain_policy = mapping['subject_domain_policy'].native

                    if issuer_domain_policy not in policy_map:
                        policy_map[issuer_domain_policy] = set()
                    policy_map[issuer_domain_policy].add(subject_domain_policy)

                    # Step 3 a
                    if issuer_domain_policy == 'any_policy' or subject_domain_policy == 'any_policy':
                        raise PathValidationError(pretty_message(
                            '''
                            The path could not be validated because %s contains
                            a policy mapping for the "any policy"
                            ''',
                            _cert_type(index, last_index, end_entity_name_override, definite=True)
                        ))

                # Step 3 b
                if valid_policy_tree is not None:
                    for mapping in cert.policy_mappings_value:
                        issuer_domain_policy = mapping['issuer_domain_policy'].native

                        # Step 3 b 1
                        if policy_mapping > 0:
                            issuer_domain_policy_match = False
                            cert_any_policy = None

                            for node in valid_policy_tree.at_depth(index):
                                if node.valid_policy == 'any_policy':
                                    cert_any_policy = node
                                if node.valid_policy == issuer_domain_policy:
                                    issuer_domain_policy_match = True
                                    node.expected_policy_set = policy_map[issuer_domain_policy]

                            if not issuer_domain_policy_match and cert_any_policy:
                                cert_any_policy.parent.add_child(
                                    issuer_domain_policy,
                                    cert_any_policy.qualifier_set,
                                    policy_map[issuer_domain_policy]
                                )

                        # Step 3 b 2
                        elif policy_mapping == 0:
                            for node in valid_policy_tree.at_depth(index):
                                if node.valid_policy == issuer_domain_policy:
                                    node.parent.remove_child(node)
                            for node in valid_policy_tree.walk_up(index - 1):
                                if not node.children:
                                    node.parent.remove_child(node)
                            if len(valid_policy_tree.children) == 0:
                                valid_policy_tree = None

            # Step 3 c
            working_issuer_name = cert.subject

            # Steps 3 d-f

            # Handle inheritance of DSA parameters from a signing CA to the
            # next in the chain
            copy_params = None
            if cert.public_key.algorithm == 'dsa' and cert.public_key.hash_algo is None:
                if working_public_key.algorithm == 'dsa':
                    copy_params = working_public_key['algorithm']['parameters'].copy()

            working_public_key = cert.public_key

            if copy_params:
                working_public_key['algorithm']['parameters'] = copy_params

            # Step 3 g skipped since it relates to name constraints

            # Step 3 h
            if not cert.self_issued:
                # Step 3 h 1
                if explicit_policy != 0:
                    explicit_policy -= 1
                # Step 3 h 2
                if policy_mapping != 0:
                    policy_mapping -= 1
                # Step 3 h 3
                if inhibit_any_policy != 0:
                    inhibit_any_policy -= 1

            # Step 3 i
            if cert.policy_constraints_value:
                # Step 3 i 1
                require_explicit_policy = cert.policy_constraints_value['require_explicit_policy'].native
                if require_explicit_policy is not None and require_explicit_policy < explicit_policy:
                    explicit_policy = require_explicit_policy
                # Step 3 i 2
                inhibit_policy_mapping = cert.policy_constraints_value['inhibit_policy_mapping'].native
                if inhibit_policy_mapping is not None and inhibit_policy_mapping < policy_mapping:
                    policy_mapping = inhibit_policy_mapping

            # Step 3 j
            if cert.inhibit_any_policy_value:
                inhibit_any_policy = min(cert.inhibit_any_policy_value.native, inhibit_any_policy)

            # Step 3 k
            if not cert.ca:
                raise PathValidationError(pretty_message(
                    '''
                    The path could not be validated because %s is not a CA
                    ''',
                    _cert_type(index, last_index, end_entity_name_override, definite=True)
                ))

            # Step 3 l
            if not cert.self_issued:
                if max_path_length == 0:
                    raise PathValidationError(pretty_message(
                        '''
                        The path could not be validated because it exceeds the
                        maximum path length
                        '''
                    ))
                max_path_length -= 1

            # Step 3 m
            if cert.max_path_length is not None and cert.max_path_length < max_path_length:
                max_path_length = cert.max_path_length

            # Step 3 n
            if cert.key_usage_value and 'key_cert_sign' not in cert.key_usage_value.native:
                raise PathValidationError(pretty_message(
                    '''
                    The path could not be validated because %s is not allowed
                    to sign certificates
                    ''',
                    _cert_type(index, last_index, end_entity_name_override, definite=True)
                ))

        # Step 3 o
        # Check for critical unsupported extensions
        supported_extensions = set([
            'authority_information_access',
            'authority_key_identifier',
            'basic_constraints',
            'crl_distribution_points',
            'extended_key_usage',
            'freshest_crl',
            'key_identifier',
            'key_usage',
            'ocsp_no_check',
            'certificate_policies',
            'policy_mappings',
            'policy_constraints',
            'inhibit_any_policy',
        ])
        unsupported_critical_extensions = cert.critical_extensions - supported_extensions
        if unsupported_critical_extensions:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because %s contains the
                following unsupported critical extension%s: %s
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True),
                's' if len(unsupported_critical_extensions) != 1 else '',
                ', '.join(sorted(unsupported_critical_extensions)),
            ))

        if validation_context:
            completed_path = completed_path.copy().append(cert)
            validation_context.record_validation(cert, completed_path)

        index += 1

    # Step 4: wrap-up procedure

    # Step 4 a
    if explicit_policy != 0:
        explicit_policy -= 1

    # Step 4 b
    if cert.policy_constraints_value:
        if cert.policy_constraints_value['require_explicit_policy'].native == 0:
            explicit_policy = 0

    # Steps 4 c-e skipped since this method doesn't output it
    # Step 4 f skipped since this method defers that to the calling application

    # Step 4 g

    # Step 4 g i
    if valid_policy_tree is None:
        intersection = None

    # Step 4 g ii
    else:
        intersection = valid_policy_tree

    # Step 4 g iii is skipped since the initial policy set is always any_policy

    if explicit_policy == 0 and intersection is None:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because there is no valid set of
            policies for %s
            ''',
            _cert_type(last_index, last_index, end_entity_name_override, definite=True)
        ))

    return cert
