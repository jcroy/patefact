"""Tests for ASN-org network-profile classification (opendir.analyze.ownership)."""
from opendir.analyze.ownership import network_profile, profile_breakdown


def test_hyperscalers_are_cloud():
    for org, disp in [
        ("Amazon Technologies Inc.", "Amazon AWS"),
        ("Amazon Data Services NoVa", "Amazon AWS"),
        ("DigitalOcean, LLC", "DigitalOcean"),
        ("OVH SAS", "OVH"),
        ("Hetzner Online GmbH", "Hetzner"),
        ("Google LLC", "Google Cloud"),
        ("Aliyun Computing Co., LTD", "Alibaba Cloud"),
    ]:
        cat, provider = network_profile(org)
        assert cat == "cloud", f"{org} -> {cat}"
        assert provider == disp


def test_vps_and_shared_hosting_are_hosting():
    for org in ["BisectHosting", "Contabo GmbH", "HostPapa", "Hostwinds Seattle",
                "Unified Layer", "Newfold Digital, Inc."]:
        assert network_profile(org)[0] == "hosting", org


def test_residential_and_academic_and_business():
    assert network_profile("Comcast Cable Communications")[0] == "residential"
    assert network_profile("Vodafone Broadband")[0] == "residential"
    assert network_profile("Massachusetts Institute of Technology")[0] == "academic"
    assert network_profile("Some Random Company Ltd")[0] == "business"


def test_empty_is_unknown():
    assert network_profile("")[0] == "unknown"
    assert network_profile(None) == ("unknown", "Unknown")


def test_profile_breakdown_counts_categories_and_providers():
    orgs = ["Amazon Technologies Inc.", "Amazon.com, Inc.", "DigitalOcean, LLC",
            "BisectHosting", "Comcast Cable"]
    cats, provs = profile_breakdown(orgs)
    assert cats["cloud"] == 3          # 2x Amazon + 1 DO
    assert cats["hosting"] == 1        # BisectHosting
    assert cats["residential"] == 1    # Comcast
    assert provs["Amazon AWS"] == 2    # both Amazon orgs collapse to one provider
