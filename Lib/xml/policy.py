"""XML parser policy

"""


class XMLParserPolicy:
    def apply_policy(self, parser, *, external_entity_parser=False):
        pass


DEFAULT_POLICY = XMLParserPolicy()


def apply_policy(parser, policy=None, *, external_entity_parser=False):
    """Apply a XML parser policy

    :param parser: pyexpat.XMLParserType instance
    :param policy: XML policy object
    :param external_entity_parser: Parser is an external entity parser
    :return: None
    """
    if policy is None:
        policy = DEFAULT_POLICY
    policy.apply_policy(parser, external_entity_parser=external_entity_parser)


class XMLPolicyException(ValueError):
    """Base exception
    """


class DTDForbidden(XMLPolicyException):
    """Document type definition is forbidden
    """

    def __init__(self, name, sysid, pubid):
        super().__init__()
        self.name = name
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        tpl = "DTDForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class EntitiesForbidden(XMLPolicyException):
    """Entity definition is forbidden
    """

    def __init__(self, name, value, base, sysid, pubid, notation_name):
        super().__init__()
        self.name = name
        self.value = value
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name

    def __str__(self):
        tpl = "EntitiesForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class ExternalReferenceForbidden(XMLPolicyException):
    """Resolving an external reference is forbidden
    """

    def __init__(self, context, base, sysid, pubid):
        super().__init__()
        self.context = context
        self.base = base
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        tpl = "ExternalReferenceForbidden(system_id='{}', public_id={})"
        return tpl.format(self.sysid, self.pubid)


class SecureXMLParserPolicy(XMLParserPolicy):
    def __init__(self, allow_dtd=True, allow_entities=False,
                 allow_external=False):
        self.allow_dtd = allow_dtd
        self.allow_entities = allow_entities
        self.allow_external = allow_external

    def apply_policy(self, parser, *, external_entity_parser=False):
        if not self.allow_dtd:
            parser.StartDoctypeDeclHandler = self.start_doctype_decl
        if not self.allow_entities:
            parser.EntityDeclHandler = self.entity_decl
            parser.UnparsedEntityDeclHandler = self.unparsed_entity_decl
        if not self.allow_external:
            parser.ExternalEntityRefHandler = self.external_entity_ref_handler

    def start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(name, sysid, pubid)

    def entity_decl(self, name, is_parameter_entity, value, base, sysid,
                    pubid, notation_name):
        raise EntitiesForbidden(
            name, value, base, sysid, pubid, notation_name)

    def unparsed_entity_decl(self, name, base, sysid, pubid,  notation_name):
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)

    def external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(context, base, sysid, pubid)

