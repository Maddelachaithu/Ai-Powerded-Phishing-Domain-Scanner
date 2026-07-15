import re

QWERTY_ADJACENT = {
    'q': ['w', 'a', 's'],
    'w': ['q', 'e', 'a', 's', 'd'],
    'e': ['w', 'r', 's', 'd', 'f'],
    'r': ['e', 't', 'd', 'f', 'g'],
    't': ['r', 'y', 'f', 'g', 'h'],
    'y': ['t', 'u', 'g', 'h', 'j'],
    'u': ['y', 'i', 'h', 'j', 'k'],
    'i': ['u', 'o', 'j', 'k', 'l'],
    'o': ['i', 'p', 'k', 'l'],
    'p': ['o', 'l'],
    'a': ['q', 'w', 's', 'z', 'x'],
    's': ['q', 'w', 'e', 'a', 'd', 'z', 'x'],
    'd': ['w', 'e', 'r', 's', 'f', 'x', 'c'],
    'f': ['e', 'r', 't', 'd', 'g', 'c', 'v'],
    'g': ['r', 't', 'y', 'f', 'h', 'v', 'b'],
    'h': ['t', 'y', 'u', 'g', 'j', 'b', 'n'],
    'j': ['y', 'u', 'i', 'h', 'k', 'n', 'm'],
    'k': ['u', 'i', 'o', 'j', 'l', 'm'],
    'l': ['i', 'o', 'p', 'k'],
    'z': ['a', 's', 'x'],
    'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v'],
    'v': ['c', 'f', 'g', 'b'],
    'b': ['v', 'g', 'h', 'n'],
    'n': ['b', 'h', 'j', 'm'],
    'm': ['n', 'j', 'k']
}

HOMOGLYPHS = {
    'o': ['0'],
    'i': ['1'],
    'l': ['1'],
    'e': ['3'],
    'a': ['@'],
    's': ['5'],
    'g': ['9'],
    'b': ['8']
}

SUSPICIOUS_PREFIXES = ['login-', 'secure-', 'verify-', 'account-', 'support-', 'my-', 'id-']
COMMON_TLDS = ['net', 'org', 'co', 'io', 'info', 'biz', 'xyz']

def parse_domain(domain: str) -> tuple[str, str]:
    """
    Splits domain into label and tld.
    Assumes standard format label.tld.
    If multiple dots, splits on the rightmost dot.
    """
    domain = domain.lower().strip()
    parts = domain.rsplit('.', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return domain, ""

def generate_variants(domain: str) -> dict[str, set[str]]:
    """
    Generates all typosquat variants for a target domain and tags them with the techniques used.
    Returns:
        dict: {variant_domain: set(techniques)}
    """
    domain = domain.lower().strip()
    label, tld = parse_domain(domain)
    if not label or not tld:
        return {}

    variants = {}

    def add_variant(variant_label: str, variant_tld: str, technique: str):
        variant_domain = f"{variant_label}.{variant_tld}"
        if variant_domain == domain:
            return
        if variant_domain not in variants:
            variants[variant_domain] = set()
        variants[variant_domain].add(technique)

    # 1. Character omission (exemplebank.com -> exemplebnk.com)
    for i in range(len(label)):
        omitted = label[:i] + label[i+1:]
        if omitted:
            add_variant(omitted, tld, 'omission')

    # 2. Character duplication (exemplebank.com -> exempllebank.com)
    for i in range(len(label)):
        duplicated = label[:i] + label[i] * 2 + label[i+1:]
        add_variant(duplicated, tld, 'duplication')

    # 3. Adjacent-keyboard-key substitution
    for i in range(len(label)):
        char = label[i]
        if char in QWERTY_ADJACENT:
            for adj in QWERTY_ADJACENT[char]:
                substituted = label[:i] + adj + label[i+1:]
                add_variant(substituted, tld, 'adjacent-key')

    # 4. Character transposition (examplebank.com -> examplebnak.com)
    for i in range(len(label) - 1):
        transposed = label[:i] + label[i+1] + label[i] + label[i+2:]
        add_variant(transposed, tld, 'transposition')

    # 5. Homoglyph substitution (o->0, i/l->1, e->3, a->@, s->5, g->9, b->8)
    # Generate single homoglyph replacements
    for i in range(len(label)):
        char = label[i]
        if char in HOMOGLYPHS:
            for glyph in HOMOGLYPHS[char]:
                homoglyph_label = label[:i] + glyph + label[i+1:]
                add_variant(homoglyph_label, tld, 'homoglyph')

    # Generate full homoglyph replacement (replace all characters that have homoglyphs)
    full_homoglyph_chars = []
    for char in label:
        if char in HOMOGLYPHS:
            # use the first homoglyph option
            full_homoglyph_chars.append(HOMOGLYPHS[char][0])
        else:
            full_homoglyph_chars.append(char)
    full_homoglyph_label = "".join(full_homoglyph_chars)
    if full_homoglyph_label != label:
        add_variant(full_homoglyph_label, tld, 'homoglyph')

    # 6. Hyphenation (examplebank.com -> example-bank.com)
    for i in range(1, len(label)):
        hyphenated = label[:i] + '-' + label[i:]
        add_variant(hyphenated, tld, 'hyphenation')

    # 7. Common TLD swaps (.com -> .net, .org, .co, .io, .info, .biz, .xyz)
    for swap_tld in COMMON_TLDS:
        if swap_tld != tld:
            add_variant(label, swap_tld, 'tld_swap')

    # 8. Suspicious prefixes
    for prefix in SUSPICIOUS_PREFIXES:
        add_variant(prefix + label, tld, 'prefix')
        # Also handle prefixes with TLD swaps (e.g. login-examplebank.net) if generated together,
        # but let's stick to the prompt's specified single techniques. The prompt asks to:
        # "Deduplicate results, exclude the original domain itself."
        # If we want to capture combinations, we can, but simple single-technique is standard unless specified.
        # Wait, the prompt says "secure-examplebank.net" is one result in the sample payload.
        # How is "secure-examplebank.net" generated?
        # It has both the prefix "secure-" AND the TLD swap ".net"!
        # Let's read: "Suspicious prefixes (login-, secure-, verify-, account-, support-, my-, id-) ... Suspicious prefix present (login-, secure- ...)"
        # So we should generate prefixes for ALL swapped TLDs as well, or just prefix the swapped domains?
        # Let's generate: for each prefix, prepend to the label, and generate for BOTH the original TLD and all swapped TLDs!
        # E.g. for prefix in SUSPICIOUS_PREFIXES:
        #   add_variant(prefix + label, tld, 'prefix')
        #   for swap_tld in COMMON_TLDS:
        #     add_variant(prefix + label, swap_tld, 'prefix') -> and 'tld_swap'!
        # Let's check the sample result:
        # "domain": "secure-examplebank.net"
        # "reasons": [
        #    "Domain registered 25 days ago (+35)",
        #    "Contains phishing-pattern prefix 'secure-' (+25)",
        #    "Both DNS-live and certificate confirmed (+15)"
        # ]
        # It has "prefix" and "Both DNS-live and certificate confirmed (+15)", but doesn't have "tld_swap" reasons, probably because "tld_swap" only applies when "rest of name identical" (meaning it is a TLD swap only).
        # Let's support combinations like prefix + TLD swaps! It makes the scanner much more powerful and covers the sample domain in the prompt.
        for swap_tld in COMMON_TLDS:
            add_variant(prefix + label, swap_tld, 'prefix')

    # Ensure all variants are lowercased and original domain is omitted
    final_variants = {}
    for var, techniques in variants.items():
        var_lower = var.lower().strip()
        if var_lower != domain:
            # Let's convert set to list for easy JSON serialization later
            final_variants[var_lower] = list(techniques)

    return final_variants
