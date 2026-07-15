from backend.generator import generate_variants, parse_domain

def test_parse_domain():
    # Test typical domain split
    assert parse_domain("example.com") == ("example", "com")
    assert parse_domain("sub.example.net") == ("sub.example", "net")
    assert parse_domain("EXAMPLE.COM  ") == ("example", "com")
    assert parse_domain("invalid") == ("invalid", "")

def test_generate_variants_omission():
    variants = generate_variants("test.com")
    # Variants: 'est.com', 'tst.com', 'tet.com', 'tes.com'
    assert "est.com" in variants
    assert "tst.com" in variants
    assert "tet.com" in variants
    assert "tes.com" in variants
    assert "omission" in variants["est.com"]

def test_generate_variants_duplication():
    variants = generate_variants("abc.com")
    assert "aabc.com" in variants
    assert "abbc.com" in variants
    assert "abcc.com" in variants
    assert "duplication" in variants["aabc.com"]

def test_generate_variants_adjacent():
    variants = generate_variants("a.com")
    # QWERTY adjacents for 'a' are 'q', 'w', 's', 'z', 'x'
    assert "q.com" in variants
    assert "s.com" in variants
    assert "adjacent-key" in variants["q.com"]

def test_generate_variants_transposition():
    variants = generate_variants("abc.com")
    assert "bac.com" in variants
    assert "acb.com" in variants
    assert "transposition" in variants["bac.com"]

def test_generate_variants_homoglyph():
    variants = generate_variants("o.com")
    assert "0.com" in variants
    assert "homoglyph" in variants["0.com"]

def test_generate_variants_hyphenation():
    variants = generate_variants("abc.com")
    assert "a-bc.com" in variants
    assert "ab-c.com" in variants
    assert "hyphenation" in variants["a-bc.com"]

def test_generate_variants_tld_swap():
    variants = generate_variants("abc.com")
    assert "abc.net" in variants
    assert "abc.org" in variants
    assert "tld_swap" in variants["abc.net"]

def test_generate_variants_prefix():
    variants = generate_variants("abc.com")
    assert "login-abc.com" in variants
    assert "secure-abc.com" in variants
    assert "prefix" in variants["login-abc.com"]

def test_generate_variants_deduplication_and_exclusion():
    variants = generate_variants("test.com")
    # Original domain must not be in the output
    assert "test.com" not in variants
    # No empty strings or nonsense keys
    for k in variants.keys():
        assert len(k) > 0
        assert "." in k
